import copy
import json
from pathlib import Path
import shutil
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
    for name in ('platform','security-path','siem','siem-ui'):
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
    path=ui_checkout/'components/siem-ui/compose.yaml'
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
