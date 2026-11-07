"""TLS-verified local Indexer client and retryable export of Wazuh-confirmed C1."""
import base64
from datetime import datetime, timezone
import http.client
import hashlib
import json
import socket
import ssl
import time

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
    rows=store.db.execute('SELECT id,event,observed,confirmed,rule_id FROM events WHERE confirmed IS NOT NULL AND indexed IS NULL ORDER BY observed DESC LIMIT 2048').fetchall()
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
    status,_=client.request('PUT','/_index_template/xoc-events',template)
    if status!=200: raise XocError('indexer_template','Cannot install the C1 search mapping.')
    # Additive mappings cover prior local releases too. Re-export through the
    # durable outbox when mappings change so existing _source fields get indexed.
    status,_=client.request('PUT','/xoc-events-*/_mapping?allow_no_indices=true',template['template']['mappings'])
    if status not in (200,404): raise XocError('indexer_mapping','Cannot reconcile the C1 index mapping.')
    store=Store('/var/lib/xocrange/siem')
    digest=hashlib.sha256(json.dumps(template,sort_keys=True).encode()).hexdigest()
    status,identity=client.request('GET','/')
    cluster=identity.get('cluster_uuid')
    if status!=200 or not isinstance(cluster,str) or cluster=='_na_':
        raise XocError('indexer_identity','Cannot identify the initialized Indexer data store.')
    with store.transaction():
        if store.cursor('indexer-mapping') != digest or store.cursor('indexer-cluster') != cluster:
            store.db.execute('UPDATE events SET indexed=NULL WHERE confirmed IS NOT NULL')
            store.set_cursor('indexer-mapping',digest)
            store.set_cursor('indexer-cluster',cluster)
    store.db.close()
    # ISM persists and runs inside Indexer, including when the host collector is down.
    policy={'policy':{'description':'xOC normalized events: seven-day index retention','default_state':'hot','states':[{'name':'hot','actions':[],'transitions':[{'state_name':'delete','conditions':{'min_index_age':'7d'}}]},{'name':'delete','actions':[{'delete':{}}],'transitions':[]}],'ism_template':[{'index_patterns':['xoc-events-*'],'priority':100}]}}
    status,_=client.request('GET','/_plugins/_ism/policies/xoc-events-retention')
    if status==404:
        status,_=client.request('PUT','/_plugins/_ism/policies/xoc-events-retention',policy)
        if status!=201: raise XocError('indexer_retention','Cannot install the index retention policy.')
    elif status!=200: raise XocError('indexer_retention','Cannot inspect the index retention policy.')
    today=datetime.now(timezone.utc).strftime('%Y.%m.%d')
    status,result=client.request('PUT','/xoc-events-'+today,{})
    if status not in (200,400) or status==400 and result.get('error',{}).get('type')!='resource_already_exists_exception':
        raise XocError('indexer_create','Cannot initialize the C1 index.')
    while True:
        try:
            status,_=client.request('GET','/siem/api/status',service='dashboard')
            if status==200: break
        except XocError: pass
        if time.monotonic()>=deadline:
            raise XocError('dashboard_start_timeout','Dashboard did not become ready within the startup deadline.')
        time.sleep(3)
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
    status,result=client.request('POST','/siem/api/saved_objects/_bulk_create?overwrite=false',objects,service='dashboard')
    saved=result.get('saved_objects',[])
    if status!=200 or len(saved)!=len(objects) or any(row.get('error',{}).get('statusCode',0) not in (0,409) for row in saved):
        raise XocError('dashboard_objects','Cannot initialize the Core saved searches and dashboard.')
    return {'status':'ready','url':'https://'+client.credentials['public_host']+'/siem/'}
