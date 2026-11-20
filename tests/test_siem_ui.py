import copy
import json
from pathlib import Path
import shutil
import subprocess
import ssl

import pytest
import yaml

from xocrange.errors import XocError
from xocrange.event_store import Store
from xocrange.indexer import bulk_payload, export
from xocrange.planner import plan
from xocrange.ui_setup import dashboard_config, indexer_config, ingress_config, private_json, public_host

ROOT=Path(__file__).resolve().parents[1]


@pytest.fixture
def ui_checkout(tmp_path):
    for name in ('platform','security-path','siem','siem-ui','management'):
        shutil.copytree(ROOT/'components'/name,tmp_path/'components'/name)
    shutil.copytree(ROOT/'presets',tmp_path/'presets')
    return tmp_path


def ui_plan(root):
    return plan(root,preset='security-path',include=['siem-ui'],allow_experimental=True)


def test_ui_selection_only_publishes_ingress_and_enables_tls(ui_checkout):
    result=ui_plan(ui_checkout)['compose']
    assert {k for k,v in result['services'].items() if v.get('ports')}=={'ingress'}
    assert result['services']['indexer']['networks']==['int']
    assert result['services']['dashboard']['networks']==['int']
    assert result['services']['web']['environment']['XOC_SIEM_UI']=='1'
    assert 'web-tls:/run/xoc-tls:ro' in result['services']['web']['volumes']
    base=plan(ui_checkout,preset='security-path',include=['siem'],allow_experimental=True)['compose']
    assert 'ingress' not in base['services'] and 'web-tls' not in base.get('volumes',{})
    assert 'XOC_SIEM_UI' not in base['services']['web']['environment']


@pytest.mark.parametrize('role,change',[
    ('indexer',{'ports':[{'target':9200,'published':9200,'host_ip':'0.0.0.0','protocol':'tcp'}]}),
    ('dashboard',{'volumes':['/var/run/docker.sock:/var/run/docker.sock']}),
    ('ingress',{'networks':['int','user']}),
    ('indexer',{'cap_add':['SYS_ADMIN']}),
    ('dashboard',{'read_only':False}),
])
def test_ui_builtin_cannot_expand_its_privileges(ui_checkout,role,change):
    path=ui_checkout/('components/management/compose.yaml' if role=='ingress' else 'components/siem-ui/compose.yaml')
    data=yaml.safe_load(path.read_text());data['services'][role].update(change);path.write_text(yaml.safe_dump(data))
    with pytest.raises(XocError):ui_plan(ui_checkout)


@pytest.mark.parametrize('value',['https://xoc.test','xoc.test:443','xoc\nInclude /tmp/x','-xoc.test','xoc_.test','999.1.1.1','a..test','/etc/passwd','xoc.test/siem'])
def test_public_host_rejects_config_injection_and_invalid_hosts(value):
    with pytest.raises(XocError):public_host(value)


def test_https_configuration_keeps_verification_and_credentials_out_of_ingress():
    secret={'kibanaserver':'service-secret','cookie':'c'*32}
    config=dashboard_config(secret)
    assert config['server.ssl.enabled'] and config['opensearch.ssl.verificationMode']=='full'
    assert config['server.rewriteBasePath'] and config['server.basePath']=='/siem'
    assert config['opensearch_security.cookie.secure']
    assert indexer_config()['plugins.security.ssl.transport.enforce_hostname_verification']
    ingress=ingress_config('School.Example.test')
    assert 'https://school.example.test' in ingress and 'ssl crt' in ingress
    assert 'http-request set-header X-Xoc-Client-IP %[src]' in ingress
    assert 'service-secret' not in ingress and '5601' not in ingress


def test_credentials_refuse_world_readable_or_symlink_files(tmp_path):
    path=tmp_path/'credentials.json';path.write_text('{}');path.chmod(0o644)
    with pytest.raises(XocError):private_json(path)
    path.chmod(0o600);assert private_json(path)=={}
    link=tmp_path/'link';link.symlink_to(path)
    with pytest.raises(XocError):private_json(link)


def indexed_store(tmp_path):
    store=Store(tmp_path/'evidence')
    with store.transaction():
        for i in range(2):
            store.ingest('suricata','ips',str(i),(ROOT/'tests/fixtures/events/suricata-alert.json').read_bytes(),observed='2026-11-07T00:00:00Z')
        store.db.execute("UPDATE events SET confirmed='2026-11-07T00:00:01Z',rule_id='110002'")
        store.set_cursor('indexer-enabled',True)
    return store


def test_bulk_export_partial_failure_retries_only_failed_id(tmp_path):
    store=indexed_store(tmp_path)
    calls=[]
    class Client:
        def request(self,method,path,body,**kwargs):
            ids=[json.loads(line)['index']['_id'] for line in body.splitlines()[::2]]
            calls.append(ids)
            return 200,{'items':[{'index':{'_id':ident,'status':201 if i==0 else 429}} for i,ident in enumerate(ids)]}
    assert export(store,Client())=='indexer_rejected'
    assert store.db.execute('SELECT COUNT(indexed) FROM events').fetchone()[0]==1
    assert export(store,Client())=='ready'
    assert calls[1]==[calls[0][1]]
    assert store.db.execute('SELECT COUNT(indexed) FROM events').fetchone()[0]==2


def test_bulk_mismatched_ack_rolls_back_and_wazuh_only_events_are_exported(tmp_path):
    store=indexed_store(tmp_path)
    class Client:
        def request(self,method,path,body,**kwargs):
            ids=[json.loads(line)['index']['_id'] for line in body.splitlines()[::2]]
            return 200,{'items':[{'index':{'_id':ids[0],'status':201}},{'index':{'_id':'wrong','status':201}}]}
    with pytest.raises(XocError):export(store,Client())
    assert store.db.execute('SELECT COUNT(indexed) FROM events').fetchone()[0]==0
    with store.transaction():store.db.execute('UPDATE events SET confirmed=NULL')
    assert export(store,Client())=='ready'


def test_index_ids_survive_replay_and_source_time_does_not_choose_retention_day(tmp_path):
    store=indexed_store(tmp_path)
    rows=store.db.execute('SELECT * FROM events').fetchall()
    first,selected=bulk_payload(rows);second,_=bulk_payload(rows)
    assert first==second and len(selected)==2
    payload=[json.loads(line) for line in first.splitlines()]
    assert payload[0]['index']['_index']=='xoc-events-2026.11.07'
    assert payload[1]['wazuh']['rule_id']=='110002'
    assert 'raw' not in payload[1]


def test_unindexed_evidence_is_retained_until_indexer_ack(tmp_path):
    store=indexed_store(tmp_path)
    store.prune(days=-1)
    assert store.db.execute('SELECT COUNT(*) FROM events').fetchone()[0]==2
    with store.transaction():store.db.execute("UPDATE events SET indexed='2026-11-07T00:00:02Z'")
    store.prune(days=-1)
    assert store.db.execute('SELECT COUNT(*) FROM events').fetchone()[0]==0


def test_native_bulk_uses_utf8_over_http(monkeypatch):
    from xocrange import indexer
    captured={}
    class Response:
        status=200
        def read(self, size):return b'{}'
    class Connection:
        def __init__(self,*args,**kwargs):pass
        def request(self,method,path,body,headers):captured['body']=body
        def getresponse(self):return Response()
        def close(self):pass
    monkeypatch.setattr(indexer,'Connection',Connection)
    client=indexer.Client.__new__(indexer.Client)
    client.user='writer';client.credentials={'writer':'test-only'};client.context=None
    client.address=lambda service:'127.0.0.1'
    body='{"index":{}}\n{"full_log":"한글 ⍰ 탐지"}\n'
    assert client.request('POST','/_bulk',body,content_type='application/x-ndjson')[0]==200
    assert captured['body']==body.encode('utf-8')


def test_local_ca_signs_only_lab_names(tmp_path):
    """ADR 0011: learners trust the local CA, so it carries DNS name constraints."""
    from xocrange import ui_setup
    from xocrange.errors import XocError
    assert ui_setup.ensure_ca(tmp_path, '192.168.16.100') is True
    text = subprocess.run(['openssl', 'x509', '-in', str(tmp_path/'ca.pem'), '-noout', '-ext', 'nameConstraints'],
                          capture_output=True, text=True, check=True).stdout
    assert all('DNS:' + n in text for n in ('xoc.range', 'lab', 'test', 'internal', 'home.arpa', 'indexer', 'dashboard'))
    ui_setup.certificate('indexer', ['indexer'], tmp_path)
    ui_setup.certificate('web', ui_setup.ingress_names('192.168.16.100') + ['alice.lab', '*.alice.lab'], tmp_path)
    ui_setup.certificate('xoc-indexer-admin', [], tmp_path)
    with pytest.raises(XocError) as refused:
        ui_setup.certificate('rogue', ['www.naver.com'], tmp_path)
    assert refused.value.code == 'certificate_name_not_allowed' and not (tmp_path/'rogue.pem').exists()
    assert ui_setup.ensure_ca(tmp_path, '192.168.16.100') is False      # an existing CA is kept
    named = tmp_path/'named'; named.mkdir()
    ui_setup.ensure_ca(named, 'core.school.example')                   # a hostname access address is allowed
    ui_setup.certificate('web', ui_setup.ingress_names('core.school.example'), named)


def test_added_agent_mapping_reexports_only_agent_events(tmp_path):
    """Adding the agent field mapping must not rewrite a multi-GiB store: the stored digest of the
    mapping without it shows the change is that addition, so only xoc-agent events go out again."""
    import copy
    from xocrange.indexer import mapping_digest, mark_reexport, reexport_scope
    template = json.loads((ROOT / 'components/siem-ui/index-template.json').read_text())
    assert 'agent' in template['template']['mappings']['properties']
    previous = copy.deepcopy(template); del previous['template']['mappings']['properties']['agent']
    old_digest = mapping_digest(previous)
    assert old_digest == __import__('hashlib').sha256(json.dumps(previous, sort_keys=True).encode()).hexdigest()
    assert reexport_scope(mapping_digest(template), template) is None
    assert reexport_scope(old_digest, template) == ('xoc-agent',)
    # The facility mapping (C1 v0.4) is scoped the same way; both additions at once reach both producers.
    before_facility = copy.deepcopy(template); del before_facility['template']['mappings']['properties']['facility']
    assert reexport_scope(mapping_digest(before_facility), template) == ('xoc-facility',)
    neither = copy.deepcopy(previous); del neither['template']['mappings']['properties']['facility']
    assert reexport_scope(mapping_digest(neither), template) == ('xoc-agent', 'xoc-facility')
    other = copy.deepcopy(previous); other['template']['mappings']['properties']['producer'] = {'type': 'text'}
    assert reexport_scope(mapping_digest(other), template) == ()        # any other change: full re-export
    assert reexport_scope(None, template) == ()
    store = Store(tmp_path / 'siem')
    receipt = {"schema_version": "xoc.agent-activity/0.1.0", "at": "2026-11-16T00:00:00Z", "role": "operator",
               "tool": "siem_search", "decision": "allow", "receipt": "rcpt-0123456789abcdef", "module": "m7-operator"}
    store.ingest('xoc-agent', 'agent-m7-operator', 1, json.dumps(receipt).encode())
    store.ingest('suricata', 'ips-eve', 1, (ROOT / 'tests/fixtures/events/suricata-alert.json').read_bytes())
    store.db.execute("UPDATE events SET confirmed='2026-11-16T00:00:01Z', indexed='2026-11-16T00:00:02Z'")
    state = lambda: dict(store.db.execute('SELECT producer, indexed IS NULL FROM events').fetchall())
    assert state() == {'xoc-agent': 0, 'suricata': 0}
    mark_reexport(store, ('xoc-agent',))
    assert state() == {'xoc-agent': 1, 'suricata': 0}
    mark_reexport(store, ())
    assert state() == {'xoc-agent': 1, 'suricata': 1}


def test_upgraded_core_pattern_gains_only_missing_template_fields():
    import json as _json
    from xocrange.indexer import add_pattern_fields
    edited={'name':'producer','type':'string','count':7,'customLabel':'Source'}
    class Fake:
        def __init__(self): self.calls=[]
        def request(self, method, path, body=None, service='indexer'):
            self.calls.append((method,path,body,service))
            if method=='GET': return 200,{'id':'xoc-events','version':'WzEsMV0=','attributes':{'title':'xoc-events-*','fields':_json.dumps([edited]),'fieldFormatMap':'{}'}}
            return 200,{}
    fields=[{'name':'producer','type':'string'},{'name':'agent.tool','type':'string'}]
    client=Fake()
    assert add_pattern_fields(client,'xoc-events',fields)==['agent.tool']
    method,path,body,service=client.calls[-1]
    assert (method,path,service)==('PUT','/siem/api/saved_objects/index-pattern/xoc-events','dashboard')
    assert body['version']=='WzEsMV0=' and set(body['attributes'])=={'fields'}
    assert _json.loads(body['attributes']['fields'])==[edited,fields[1]]   # the user's edit is kept
    again=Fake(); again.request=lambda m,p,b=None,service='indexer':(200,{'attributes':{'fields':_json.dumps(fields)}}) if m=='GET' else (_ for _ in ()).throw(AssertionError('no write'))
    assert add_pattern_fields(again,'xoc-events',fields)==[]


def test_acceptance_source_counts_are_not_cut_by_extra_producers():
    """Agent activity (C1 v0.3) is a ninth producer. A top-8 terms aggregation dropped Suricata
    (2 events in the window, versus about 10 agent records) and failed the demo Core update."""
    script=(ROOT/'scripts/verify-siem-ui.py').read_text()
    assert "'size':8" not in script
    assert script.count("{'terms':{'producer':list(SOURCES)}}")==1 and script.count("{'terms':{'data.producer':list(SOURCES)}}")==1
