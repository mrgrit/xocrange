import hashlib
import json
from pathlib import Path

import pytest

from xocrange.errors import XocError
from xocrange.event_store import Store
from xocrange.native_alerts import accept, export

ROOT=Path(__file__).resolve().parents[1]


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path/'evidence')


def alert(number='1',data=None):
    return json.dumps({'id':'1794056400.'+number,'timestamp':'2026-11-07T13:00:00.000+0000',
                      'manager':{'name':'xoc'},'rule':{'id':'5710','level':5},
                      'full_log':'sshd failed authentication','data':data or {}}).encode()


def test_original_alert_and_bytes_survive_without_c1_loop(store):
    raw=alert()
    with store.transaction():first=accept(store,raw);second=accept(store,raw)
    assert first==second
    row=store.db.execute('SELECT * FROM wazuh_alerts').fetchone()
    assert row['raw']==raw and row['sha256']==hashlib.sha256(raw).hexdigest()
    assert row['event_id'] is None
    document=json.loads(row['document']);original=json.loads(raw)
    assert all(document[k]==v for k,v in original.items())
    assert store.db.execute('SELECT COUNT(*) FROM events').fetchone()[0]==0


def test_existing_identity_with_changed_bytes_is_rejected(store):
    with store.transaction():accept(store,alert())
    with pytest.raises(XocError,match='different bytes'):
        with store.transaction():accept(store,alert().replace(b'authentication',b'other'))
    assert store.db.execute('SELECT COUNT(*) FROM wazuh_alerts').fetchone()[0]==1


def test_native_link_only_points_to_confirmed_matching_c1(store):
    with store.transaction():
        store.ingest('suricata','ips','1',(ROOT/'tests/fixtures/events/suricata-alert.json').read_bytes())
        event=json.loads(store.db.execute('SELECT event FROM events').fetchone()[0])
        store.confirm({'agent':{'id':'000'},'location':'xoc-c1','data':event,'rule':{'id':'110002'}})
        c1=json.loads(alert(data=event));c1.update(agent={'id':'000'},location='xoc-c1',rule={'id':'110002','level':3})
        accept(store,json.dumps(c1).encode())
    row=store.db.execute('SELECT * FROM wazuh_alerts').fetchone()
    assert row['event_id']==event['event_id']
    assert json.loads(row['document'])['xoc']['evidence_ref']==event['evidence']['ref']
    assert store.db.execute('SELECT COUNT(*) FROM events').fetchone()[0]==1


def test_native_partial_bulk_retries_only_failed_and_retains_unindexed(store):
    with store.transaction():
        store.set_cursor('indexer-enabled',True)
        accept(store,alert('1'));accept(store,alert('2'))
    batches=[]
    class Client:
        def request(self,method,path,body,**kwargs):
            ids=[json.loads(line)['index']['_id'] for line in body.splitlines()[::2]]
            batches.append(ids)
            return 200,{'items':[{'index':{'_id':v,'status':201 if i==0 else 429}} for i,v in enumerate(ids)]}
    assert export(store,Client())=='native_indexer_rejected'
    store.prune(days=-1)
    assert store.db.execute('SELECT COUNT(*) FROM wazuh_alerts').fetchone()[0]==1
    assert export(store,Client())=='ready' and batches[1]==[batches[0][1]]


def test_native_bulk_wrong_ack_rolls_back(store):
    with store.transaction():accept(store,alert())
    class Client:
        def request(self,*args,**kwargs):return 200,{'items':[{'index':{'_id':'wrong','status':201}}]}
    with pytest.raises(XocError):export(store,Client())
    assert store.db.execute('SELECT COUNT(indexed) FROM wazuh_alerts').fetchone()[0]==0


@pytest.mark.parametrize('value',[b'{}',b'{"id":1,"timestamp":"x","manager":{"name":"x"}}'])
def test_native_identity_must_be_usable(store,value):
    with pytest.raises(XocError):accept(store,value)
    assert store.db.execute('SELECT COUNT(*) FROM wazuh_alerts').fetchone()[0]==0


def test_stock_rule_cannot_acknowledge_a_c1_event(store):
    with store.transaction():
        store.ingest('suricata','ips','1',(ROOT/'tests/fixtures/events/suricata-alert.json').read_bytes())
        event=json.loads(store.db.execute('SELECT event FROM events').fetchone()[0])
        store.confirm({'agent':{'id':'000'},'location':'xoc-c1','data':event,'rule':{'id':'1002'}})
    assert not store.query(confirmed=True) and len(store.pending())==1


def test_external_agent_cannot_forge_local_receipt_or_evidence_link(store):
    with store.transaction():
        store.ingest('suricata','ips','1',(ROOT/'tests/fixtures/events/suricata-alert.json').read_bytes())
        event=json.loads(store.db.execute('SELECT event FROM events').fetchone()[0])
        forged=json.loads(alert(data=event));forged.update(agent={'id':'001'},location='xoc-c1',rule={'id':'110002'})
        store.confirm(forged)
        accept(store,json.dumps(forged).encode())
    assert not store.query(confirmed=True)
    assert store.db.execute('SELECT event_id FROM wazuh_alerts').fetchone()[0] is None


def test_recovery_queue_serves_fresh_and_old_events_without_duplicates(store):
    with store.transaction():
        for i in range(10):store.ingest('suricata','ips',str(i),(ROOT/'tests/fixtures/events/suricata-alert.json').read_bytes(),observed=f'2026-11-07T13:00:{i:02d}Z')
    rows=store.db.execute('SELECT id FROM events ORDER BY observed').fetchall()
    pending=store.pending(limit=4);ids=[r['id'] for r in pending]
    assert len(set(ids))==4 and rows[-1]['id'] in ids and rows[0]['id'] in ids
