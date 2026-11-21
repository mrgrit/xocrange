"""TLS-verified local Indexer client and retryable export of Wazuh-confirmed C1."""
import base64
from datetime import datetime, timezone
import http.client
import hashlib
import json
import socket
import ssl
import time
from urllib.parse import urlencode

from itertools import combinations

from .errors import XocError
from .event_store import Store, now
from .ui_setup import STATE, private_json


class Connection(http.client.HTTPSConnection):
    def __init__(self, address, name, port, context):
        super().__init__(name, port, context=context, timeout=15)
        self.address = address

    def connect(self):
        raw = socket.create_connection((self.address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


class Client:
    def __init__(self, engine, project, user='xoc-writer', state=STATE):
        self.engine, self.project, self.user = engine, project, user
        self.credentials = private_json(state/'credentials.json')
        self.context = ssl.create_default_context(cafile=str(state/'ca.pem'))
        self.addresses = {}

    def address(self, service):
        previous = self.addresses.get(service)
        if previous and time.monotonic()-previous[0] < 30:
            return previous[1]
        identifier = self.engine.run(['ps','--quiet',service],compose=True).strip()
        if not identifier:
            raise XocError('indexer_unavailable','The requested SIEM service is not running.')
        item, = json.loads(self.engine.run(['inspect',identifier]))
        labels = item['Config'].get('Labels') or {}
        if labels.get('com.docker.compose.project') != self.project or labels.get('com.docker.compose.service') != service:
            raise XocError('untrusted_indexer','The SIEM endpoint does not belong to this installation.')
        address=item['NetworkSettings']['Networks'][self.project+'_int']['IPAddress']
        self.addresses[service]=(time.monotonic(),address)
        return address

    def request(self, method, path, body=None, *, service='indexer', content_type='application/json'):
        headers={'Authorization':'Basic '+base64.b64encode((self.user+':'+self.credentials[self.user]).encode()).decode(),
                 'Content-Type':content_type,'osd-xsrf':'xoc-setup'}
        if body is not None and not isinstance(body,(str,bytes)):
            body=json.dumps(body)
        if isinstance(body,str):
            body=body.encode('utf-8')
        connection=Connection(self.address(service),service,9200 if service=='indexer' else 5601,self.context)
        try:
            connection.request(method,path,body,headers)
            response=connection.getresponse()
            data=response.read(8*1024**2+1)
            if len(data)>8*1024**2:
                raise XocError('indexer_response_limit','SIEM response exceeded its bounded read size.')
            try: value=json.loads(data)
            except (ValueError,UnicodeError): value={}
            return response.status,value
        except (OSError,http.client.HTTPException) as exc:
            self.addresses.pop(service,None)
            raise XocError('indexer_unavailable','The SIEM TLS connection failed; data remains queued.') from exc
        finally:
            connection.close()


def document(row):
    value=json.loads(row['event'])
    value['wazuh']={'confirmed_at':row['confirmed'],'rule_id':row['rule_id']}
    return value


def bulk_payload(rows, limit=4*1024**2):
    lines=[]; selected=[]; size=0
    for row in rows:
        # Partition by ingestion day so delayed source timestamps do not recreate
        # already expired historical indices. The original occurrence time remains.
        index='xoc-events-'+row['observed'][:10].replace('-','.')
        chunk=json.dumps({'index':{'_index':index,'_id':row['id']}})+'\n'+json.dumps(document(row))+'\n'
        size+=len(chunk.encode())
        if size>limit and selected: break
        lines.append(chunk);selected.append(row)
    return ''.join(lines),selected


def export(store, client):
    # Recent observations stay visible while an upgrade backfills older evidence.
    rows=store.index_batch(limit=4096)
    if not rows: return 'ready'
    payload, rows=bulk_payload(rows)
    status,result=client.request('POST','/_bulk',payload,content_type='application/x-ndjson')
    items=result.get('items',[])
    if status != 200 or len(items)!=len(rows):
        raise XocError('indexer_rejected','The Indexer did not acknowledge the complete batch.')
    failed=False
    with store.transaction():
        for row,item in zip(rows,items):
            ack=item.get('index',{})
            if ack.get('_id') != row['id']:
                raise XocError('indexer_mismatch','Indexer acknowledgment does not match its event ID.')
            if ack.get('status') in (200,201):
                store.db.execute('UPDATE events SET indexed=? WHERE id=?',(now(),row['id']))
            else: failed=True
    return 'indexer_rejected' if failed else 'ready'


# Mapping additions whose fields only these producers carry. Adding one re-exports just
# those events; a full re-export of a multi-GiB store cannot finish within the service
# start deadline (it rewrites every row before the Indexer sees one).
SCOPED_FIELDS = {'agent': ('xoc-agent',), 'facility': ('xoc-facility',)}


def mapping_digest(template, without=()):
    template = json.loads(json.dumps(template))
    for name in without:
        template['template']['mappings']['properties'].pop(name, None)
    return hashlib.sha256(json.dumps(template, sort_keys=True).encode()).hexdigest()


def reexport_scope(stored, template):
    """None: mapping unchanged. (): re-export everything. Producers: re-export only theirs,
    because the stored mapping equals this one without some scoped field additions."""
    if stored == mapping_digest(template):
        return None
    present = [name for name in SCOPED_FIELDS if name in template['template']['mappings']['properties']]
    for size in range(1, len(present) + 1):
        for added in combinations(present, size):
            if stored == mapping_digest(template, added):
                return tuple(sorted({p for name in added for p in SCOPED_FIELDS[name]}))
    return ()


def mark_reexport(store, scope):
    """Queue events for the Indexer again: only the given producers' events, or everything."""
    if scope:
        marks=','.join('?'*len(scope))
        store.db.execute(f'UPDATE events INDEXED BY events_producer_time SET indexed=NULL WHERE producer IN ({marks}) AND confirmed IS NOT NULL',scope)
    else:
        store.db.execute('UPDATE events SET indexed=NULL WHERE confirmed IS NOT NULL')
        store.db.execute('UPDATE wazuh_alerts SET indexed=NULL')


def add_pattern_fields(client, pattern_id, fields):
    """Append template fields missing from a saved index pattern; keep everything else."""
    path='/siem/api/saved_objects/index-pattern/'+pattern_id
    status,current=client.request('GET',path,service='dashboard')
    try:
        existing=json.loads(current['attributes'].get('fields') or '[]') if status==200 else None
    except (KeyError,TypeError,ValueError):
        existing=None
    if not isinstance(existing,list):
        raise XocError('dashboard_objects','Cannot read the Core index pattern fields.')
    names={f.get('name') for f in existing if isinstance(f,dict)}
    missing=[f for f in fields if f['name'] not in names]
    if not missing: return []
    body={'attributes':{'fields':json.dumps(existing+missing)}}
    if current.get('version'): body['version']=current['version']
    status,_=client.request('PUT',path,body,service='dashboard')
    if status!=200:
        raise XocError('dashboard_objects','Cannot add new fields to the Core index pattern.')
    return [f['name'] for f in missing]


def initialize(client, root, timeout=240):
    deadline=time.monotonic()+timeout
    while True:
        try:
            status,health=client.request('GET','/_cluster/health')
            if status==200 and health.get('status') in ('yellow','green'): break
        except XocError: pass
        if time.monotonic()>=deadline:
            raise XocError('indexer_start_timeout','Indexer did not become healthy within the startup deadline.')
        time.sleep(3)
    template=json.loads((root/'components/siem-ui/index-template.json').read_text())
    # Default security YAML is read only for an empty security index. Reconcile
    # this installation-owned role on upgrades without resetting other users.
    from .ui_setup import writer_role
    role=writer_role();role.pop('reserved')
    status,_=client.request('PUT','/_plugins/_security/api/roles/xoc_ingest',role)
    if status not in (200,201):raise XocError('indexer_writer_role','Cannot reconcile the ingestion role.')
    # Preserve upstream native field mappings for the Wazuh plugin. Separate
    # namespaces prevent normalized C1 fields from replacing native alert fields.
    native=json.loads((root/'components/siem-ui/wazuh-template.json').read_text())
    native['settings']['index.number_of_shards']='1'
    native['settings']['index.auto_expand_replicas']='false'
    native['mappings']['properties']['xoc']={'properties':{name:{'type':'keyword'} for name in ('event_id','evidence_ref','native_alert_id','input_id','producer','analysis_route')}}
    status,_=client.request('PUT','/_template/xoc-wazuh',native)
    if status!=200:raise XocError('native_template','Cannot install native Wazuh mappings.')
    status,_=client.request('PUT','/wazuh-alerts-*/_mapping?allow_no_indices=true',{'properties':{'xoc':native['mappings']['properties']['xoc']}})
    if status not in (200,404):raise XocError('native_mapping','Cannot reconcile native link fields.')
    status,_=client.request('PUT','/_index_template/xoc-events',template)
    if status!=200: raise XocError('indexer_template','Cannot install the C1 search mapping.')
    # Additive mappings cover prior local releases too. Re-export through the
    # durable outbox when mappings change so existing _source fields get indexed.
    status,_=client.request('PUT','/xoc-events-*/_mapping?allow_no_indices=true',template['template']['mappings'])
    if status not in (200,404): raise XocError('indexer_mapping','Cannot reconcile the C1 index mapping.')
    store=Store('/var/lib/xocrange/siem')
    digest=mapping_digest(template)
    status,identity=client.request('GET','/')
    cluster=identity.get('cluster_uuid')
    if status!=200 or not isinstance(cluster,str) or cluster=='_na_':
        raise XocError('indexer_identity','Cannot identify the initialized Indexer data store.')
    with store.transaction():
        scope=() if store.cursor('indexer-cluster') != cluster else reexport_scope(store.cursor('indexer-mapping'),template)
        if scope is not None:
            mark_reexport(store,scope)
            store.set_cursor('indexer-mapping',digest)
            store.set_cursor('indexer-cluster',cluster)
    store.db.close()
    # Host retention can see pending delivery state; age-only ISM cannot.
    # Detach only the two policies installed by earlier xOC releases.
    for policy_id, pattern in [('xoc-events-retention','xoc-events-*'),('xoc-native-retention','wazuh-alerts-4.x-*')]:
        code, data = client.request('GET','/_plugins/_ism/policies/'+policy_id)
        if code == 404: continue
        if code != 200: raise XocError('indexer_retention','Cannot inspect the previous retention policy.')
        code, explained = client.request('GET','/_plugins/_ism/explain/'+pattern)
        if code != 200: raise XocError('indexer_retention','Cannot inspect managed index state.')
        for name, metadata in explained.items():
            if not isinstance(metadata,dict): continue
            current = metadata.get('policy_id') or metadata.get('index.plugins.index_state_management.policy_id') or metadata.get('index.opendistro.index_state_management.policy_id')
            if current != policy_id: continue
            import re
            if not re.fullmatch(r'(?:xoc-events-|wazuh-alerts-4\.x-)20\d\d\.\d\d\.\d\d',name): continue
            code, reply = client.request('POST','/_plugins/_ism/remove/'+name)
            if code != 200 or reply.get('failures'): raise XocError('indexer_retention','Cannot detach the previous retention policy.')
        code,_ = client.request('DELETE','/_plugins/_ism/policies/'+policy_id)
        if code not in (200,404): raise XocError('indexer_retention','Cannot retire the previous retention policy.')
    today=datetime.now(timezone.utc).strftime('%Y.%m.%d')
    status,result=client.request('PUT','/xoc-events-'+today,{})
    if status not in (200,400) or status==400 and result.get('error',{}).get('type')!='resource_already_exists_exception':
        raise XocError('indexer_create','Cannot initialize the C1 index.')
    status,result=client.request('PUT','/wazuh-alerts-4.x-'+today,{})
    if status not in (200,400) or status==400 and result.get('error',{}).get('type')!='resource_already_exists_exception':
        raise XocError('native_index_create','Cannot initialize the native alert index.')
    while True:
        try:
            status,_=client.request('GET','/siem/api/status',service='dashboard')
            if status==200: break
        except XocError: pass
        if time.monotonic()>=deadline:
            raise XocError('dashboard_start_timeout','Dashboard did not become ready within the startup deadline.')
        time.sleep(3)
    # A first login must also work before the first scheduled statistics job.
    # Use Wazuh's ISO-week names and its own templates, without fabricated data.
    week=datetime.now(timezone.utc).isocalendar()
    for name,prefix in [('wazuh-agent','wazuh-monitoring-'),('wazuh-statistics','wazuh-statistics-')]:
        while True:
            status,_=client.request('GET','/_template/'+name)
            if status==200:break
            if status!=404 or time.monotonic()>=deadline:raise XocError('native_dashboard_template','Native Dashboard templates are not ready.')
            time.sleep(2)
        status,result=client.request('PUT','/'+prefix+str(week.year)+'.'+str(week.week)+'w',{})
        if status not in (200,400) or status==400 and result.get('error',{}).get('type')!='resource_already_exists_exception':
            raise XocError('native_dashboard_index','Cannot initialize native monitoring indices.')
    objects=[json.loads(line) for line in (root/'components/siem-ui/saved-objects.ndjson').read_text().splitlines()]
    fields=[]
    def visit(properties, prefix=''):
        for name,field in properties.items():
            name=prefix+name
            if 'properties' in field: visit(field['properties'],name+'.')
            else:
                kind=field['type']; dtype={'keyword':'string','text':'string','integer':'number','long':'number'}.get(kind,kind)
                fields.append({'name':name,'type':dtype,'esTypes':[kind],'searchable':True,'aggregatable':kind!='text','readFromDocValues':kind!='text','scripted':False})
    visit(template['template']['mappings']['properties'])
    objects[0]['attributes']['fields']=json.dumps(fields)
    # Provision the native index patterns before the first browser health check.
    # Never replace an existing user-edited pattern. Manager-ready startup lets
    # Wazuh's own monitoring/statistics jobs initialize their real indices.
    for pattern,time_field in [('wazuh-alerts-*','timestamp'),('wazuh-monitoring-*','timestamp'),('wazuh-statistics-*','timestamp')]:
        status,result=client.request('GET','/siem/api/index_patterns/_fields_for_wildcard?'+urlencode({'pattern':pattern}),service='dashboard')
        if status!=200 or not isinstance(result.get('fields'),list):raise XocError('native_dashboard_fields','Cannot initialize native field definitions.')
        objects.append({'type':'index-pattern','id':pattern,'attributes':{'title':pattern,'timeFieldName':time_field,'fields':json.dumps(result['fields'])}})
    status,result=client.request('POST','/siem/api/saved_objects/_bulk_create?overwrite=false',objects,service='dashboard')
    saved=result.get('saved_objects',[])
    if status!=200 or len(saved)!=len(objects) or any(row.get('error',{}).get('statusCode',0) not in (0,409) for row in saved):
        raise XocError('dashboard_objects','Cannot initialize the Core saved searches and dashboard.')
    # overwrite=false keeps an existing pattern, so a field the template gained later
    # (C1 v0.3 agent.*) would never reach Discover's field list on an upgraded install.
    add_pattern_fields(client,objects[0]['id'],fields)
    return {'status':'ready','url':'https://'+client.credentials['public_host']+'/siem/'}
