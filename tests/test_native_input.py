import hashlib
import json
from pathlib import Path

import pytest

from xocrange.documents import canonical
from xocrange.errors import XocError
from xocrange.event_store import Store
from xocrange.events import Context, normalize
from xocrange.native_input import confirm, delivery, frames, pending
from xocrange.native_alerts import accept, document

ROOT = Path(__file__).resolve().parents[1]

FIXTURES=Path(__file__).parent/'fixtures/events'
FILES={'nftables':'nftables-drop.log','suricata':'suricata-alert.json','modsecurity':'modsecurity-audit.json',
       'osquery':'osquery-results.json','sysmon':'sysmon-process.xml','auditd':'auditd-exec.log',
       'apache-access':'apache-access.json','apache-error':'apache-error.log'}
DECODERS={'nftables':'xoc-nftables','suricata':'json','modsecurity':'json','osquery':'json',
          'sysmon':'json','auditd':'auditd','apache-access':'json','apache-error':'apache-errorlog'}


@pytest.fixture
def store(tmp_path):
    value=Store(tmp_path/'evidence')
    with value.transaction():value.set_cursor('native-input-enabled',True)
    yield value
    value.db.close()


def ingest(store,source='suricata',raw=None):
    raw=(FIXTURES/FILES[source]).read_bytes() if raw is None else raw
    with store.transaction():ref=store.ingest(source,'trusted-'+source,'1',raw)
    return ref,raw


def receipt(frame,decoder):
    return {'agent':{'id':'000'},'location':'xoc-native/'+frame['id']+'/'+frame['source'],
            'decoder':{'name':decoder},'full_log':frame['payload']}


@pytest.mark.parametrize('source',FILES)
def test_real_processing_receipt_confirms_eight_sources_without_creating_an_alert(store,source):
    ref,raw=ingest(store,source)
    frame,=pending(store)
    assert frame['source']==source and 'xoc.event/0.2.0' not in frame['payload']
    with store.transaction():
        store.db.execute("UPDATE native_inputs SET sent='2099-01-01T00:00:00Z'")
    assert pending(store)==[] and store.db.execute('SELECT confirmed FROM native_inputs').fetchone()[0] is None
    with store.transaction():confirm(store,receipt(frame,DECODERS[source]))
    assert store.db.execute('SELECT confirmed FROM native_inputs').fetchone()[0]
    assert store.db.execute('SELECT raw,sha256 FROM records WHERE ref=?',(ref,)).fetchone()[:]==(raw,hashlib.sha256(raw).hexdigest())
    assert store.db.execute('SELECT COUNT(*) FROM wazuh_alerts').fetchone()[0]==0
    assert store.db.execute('SELECT COUNT(confirmed) FROM events').fetchone()[0]==0


def test_query_batches_keep_native_columns_and_corresponding_c1_identity(store):
    raw=json.dumps({'name':'fixture','unixTime':1794056400,'hostIdentifier':'fixture',
                    'diffResults':{'added':[{'pid':'42','cmdline':'private argument'}], 'removed':[{'pid':'43'}]}}).encode()
    ingest(store,'osquery',raw)
    rows=store.db.execute('SELECT ordinal,event_id FROM native_inputs ORDER BY ordinal').fetchall()
    native=frames('osquery',raw)
    assert [json.loads(v)['osquery']['action'] for v in native]==['added','removed']
    assert json.loads(native[0])['osquery']['columns']['cmdline']=='private argument'
    assert len({r['event_id'] for r in rows})==2
    assert all('cmdline' not in r[0] for r in store.db.execute('SELECT event FROM events'))


def test_empty_query_snapshot_still_has_one_processed_input(store):
    ingest(store,'osquery',json.dumps({'name':'empty','unixTime':1794056400,'snapshot':[]}).encode())
    assert len(pending(store))==1
    assert json.loads(pending(store)[0]['payload'])['osquery']['columns']=={}


def test_sysmon_bridge_keeps_linux_identity_and_unescapes_xml_values(store):
    raw=(FIXTURES/'sysmon-process.xml').read_bytes().replace(b'DO-NOT-EXPORT',b'a &amp; b')
    ingest(store,'sysmon',raw)
    data=json.loads(pending(store)[0]['payload'])['sysmon_linux']
    assert data['provider']=='Linux-Sysmon' and data['event_id']==1
    assert data['eventdata']['CommandLine']=='a & b'
    assert 'win' not in json.loads(pending(store)[0]['payload'])


def test_sensor_banner_is_not_counted_as_a_decoded_event(store):
    ingest(store,'sysmon',b'Sysmon v1.6.0')
    assert not pending(store)
    assert store.db.execute('SELECT decoder FROM native_inputs').fetchone()[0]=='sensor-diagnostic'


@pytest.mark.parametrize('messages,mode,blocked', [
    (['Access denied with code 403 (phase 2). [id "949110"]'], 'ENABLED', True),
    (['Warning. [data "Access denied with code 403 (phase 2)."]'], 'ENABLED', False),
    (['Warning.', 'Access denied with code 403 (phase 2).'], 'ENABLED', True),
    (['Access denied with code 403 (phase 2).'], 'DETECTION_ONLY', False),
    ([], 'ENABLED', False),
])
def test_modsecurity_ahz_intervention_without_status_and_untrusted_text(messages,mode,blocked):
    value=json.loads((FIXTURES/'modsecurity-audit.json').read_bytes())
    value['response']={'body':'Access denied with code 403 (phase 2).'}
    value['audit_data'].update(messages=messages,engine_mode=mode)
    value['xoc_modsecurity']={'intervention':True}
    output=json.loads(frames('modsecurity',json.dumps(value).encode())[0])
    assert output['xoc_modsecurity']['intervention'] is blocked
    assert output['audit_data']==value['audit_data']


@pytest.mark.parametrize('mutation',['identity','source','payload','missing-payload'])
def test_processing_receipt_rejects_wrong_identity_or_bytes(store,mutation):
    ingest(store);frame,=pending(store);value=receipt(frame,'json')
    if mutation=='identity':value['location']='xoc-native/'+'b'*64+'/suricata'
    if mutation=='source':value['location']='xoc-native/'+frame['id']+'/osquery'
    if mutation=='payload':value['full_log']+='changed'
    if mutation=='missing-payload':value.pop('full_log')
    with pytest.raises(XocError):
        with store.transaction():confirm(store,value)
    assert store.db.execute('SELECT confirmed FROM native_inputs').fetchone()[0] is None


def test_unknown_decoder_is_visible_and_retains_pending_evidence(store):
    ingest(store);frame,=pending(store)
    with store.transaction():confirm(store,receipt(frame,'unknown'))
    store.prune(days=-1)
    assert store.db.execute('SELECT error FROM native_inputs').fetchone()[0]=='native_decoder_missing'
    assert store.status()['native_input_errors']==1 and store.status()['status']=='degraded'
    assert store.db.execute('SELECT COUNT(*) FROM records').fetchone()[0]==1


def test_duplicate_bad_decoder_receipt_does_not_block_other_inputs_and_can_recover(store):
    ingest(store,'suricata');bad=next(p for p in pending(store) if p['source']=='suricata')
    ingest(store,'osquery');good=next(p for p in pending(store) if p['source']=='osquery')
    with store.transaction():confirm(store,receipt(bad,'unknown'))
    with store.transaction():
        confirm(store,receipt(bad,'unknown'))
        confirm(store,receipt(good,'json'))
    assert store.db.execute('SELECT confirmed FROM native_inputs WHERE id=?',(good['id'],)).fetchone()[0]
    with store.transaction():confirm(store,receipt(bad,'json'))
    assert store.db.execute('SELECT error FROM native_inputs WHERE id=?',(bad['id'],)).fetchone()[0] is None


def test_native_frame_limit_does_not_truncate_or_discard_the_original(store):
    value=json.loads((FIXTURES/'modsecurity-audit.json').read_bytes())
    value['response']['body']='x'*61000
    ref,raw=ingest(store,'modsecurity',json.dumps(value).encode())
    assert store.db.execute('SELECT error FROM records WHERE ref=?',(ref,)).fetchone()[0] is None
    assert store.db.execute('SELECT error FROM native_inputs').fetchone()[0]=='native_frame_limit'
    assert not pending(store)
    store.prune(days=-1)
    assert store.db.execute('SELECT raw FROM records').fetchone()[0]==raw


def test_original_raw_alert_is_linked_and_equivalent_transport_replay_is_deduplicated(store):
    ref,_=ingest(store);frame,=pending(store)
    value=receipt(frame,'json')|{'id':'1','timestamp':'2026-11-07T01:00:00Z','manager':{'name':'xoc-manager'},
                               'rule':{'id':'86601','level':3,'firedtimes':1},'data':{'event_type':'alert'}}
    first=canonical(value)
    with store.transaction():identifier=accept(store,first)
    value['id']='2';value['timestamp']='2026-11-07T01:00:05Z';value['rule']['firedtimes']=2
    with store.transaction():assert accept(store,canonical(value))==identifier
    row=store.db.execute('SELECT * FROM wazuh_alerts').fetchone();doc=json.loads(document(row))
    assert row['raw']==first and doc['xoc']['evidence_ref']==ref and doc['xoc']['input_id']==frame['id']
    assert doc['xoc']['analysis_route']=='raw' and doc['xoc']['producer']=='suricata'
    assert store.db.execute('SELECT COUNT(*) FROM wazuh_alerts').fetchone()[0]==1
    assert store.db.execute('SELECT confirmed FROM events').fetchone()[0] is None


def test_native_alert_cannot_acknowledge_or_break_c1_with_payload_event_id(store):
    ingest(store);identifier=store.db.execute('SELECT id FROM events').fetchone()[0]
    with store.transaction():store.confirm({'rule':{'id':'86601'},'data':{'event_id':identifier,'producer':'forged'}})
    assert store.db.execute('SELECT confirmed FROM events').fetchone()[0] is None


def test_pending_native_analysis_and_pending_native_index_both_retain_raw_evidence(store):
    ingest(store);frame,=pending(store)
    with store.transaction():
        store.set_cursor('indexer-enabled',True)
        store.db.execute("UPDATE events SET confirmed='done',indexed='done'")
    store.prune(days=-1)
    assert store.db.execute('SELECT COUNT(*) FROM records').fetchone()[0]==1
    value=receipt(frame,'json')|{'id':'1','timestamp':'2026-11-07T01:00:00Z','manager':{'name':'xoc'},'rule':{'id':'86601'}}
    with store.transaction():confirm(store,value);accept(store,canonical(value))
    store.prune(days=-1)
    assert store.db.execute('SELECT COUNT(*) FROM records').fetchone()[0]==1
    with store.transaction():store.db.execute("UPDATE wazuh_alerts SET indexed='done'")
    store.prune(days=-1)
    assert store.db.execute('SELECT COUNT(*) FROM records').fetchone()[0]==0
    assert store.db.execute('SELECT COUNT(*) FROM native_inputs').fetchone()[0]==0


def test_native_enablement_does_not_replay_prior_history_or_duplicate_input_ids(store):
    with store.transaction():store.set_cursor('native-input-enabled',False)
    ref,raw=ingest(store)
    with store.transaction():
        store.set_cursor('native-input-enabled',True)
        assert store.ingest('suricata','trusted-suricata','1',raw)==ref
    assert not pending(store)
    with store.transaction():store.ingest('suricata','trusted-suricata','2',raw)
    assert len(pending(store))==1


def test_apache_native_request_retains_correlation_without_exporting_url_or_headers():
    raw=b'192.0.2.10 - - [07/Nov/2026:13:00:00 +0000] "GET /private?token=secret HTTP/1.1" 403 42 xoc_id=fixture-123'
    context=Context('community','local','web','fixture://one','2026-11-07T13:00:00Z')
    event,=normalize('apache-access',raw,context)
    assert event['correlation']['transaction_id']=='fixture-123'
    assert event['http']['status_code']==403 and event['event']['outcome']=='failure'
    assert 'secret' not in json.dumps(event) and 'private' not in json.dumps(event)
    assert frames('apache-access',raw)==[raw.decode()]


def test_apache_learner_request_keeps_user_agent_in_raw_only():
    raw=b'192.0.2.10 - - [15/Nov/2026:13:00:00 +0000] "GET /index.php?id=1 HTTP/1.1" 200 42 "-" "sqlmap/1.8.4 \\"x\\"" xoc_id=fixture-124'
    context=Context('community','local','web','fixture://one','2026-11-15T13:00:00Z')
    event,=normalize('apache-access',raw,context)
    assert event['correlation']['transaction_id']=='fixture-124' and event['http']=={'status_code':200,'method':'GET','bytes':42}
    assert 'sqlmap' not in json.dumps(event)  # C1 carries no header; the evidence is the hashed raw line
    assert frames('apache-access',raw)==[raw.decode()]
    empty=b'192.0.2.10 - - [15/Nov/2026:13:00:00 +0000] "-" 408 0 "-" "-" xoc_id=-'
    assert normalize('apache-access',empty,context)[0]['http']=={'status_code':408,'bytes':0}


def test_apache_log_formats_record_user_agent_for_lab_traffic_only():
    conf=(ROOT/'components/security-path/web/apache.conf').read_text()
    native,=[l for l in conf.splitlines() if l.endswith(' xoc_native')]
    management,=[l for l in conf.splitlines() if l.endswith(' xoc_management')]
    assert '%{User-Agent}i' in native and '%{Referer}i' not in native and 'Cookie' not in native
    assert '%{' not in management.replace('%{UNIQUE_ID}e','') and '%r' not in management


def test_archive_receipt_split_across_reads_survives_collector_restart(store):
    import base64
    from xocrange.collector import Collector
    ingest(store);frame,=pending(store);raw=canonical(receipt(frame,'json'))+b'\n'
    def chunk(data,offset):
        return {'key':'archive:inode','offset':offset,'reset':False,'data':base64.b64encode(data).decode(),'anchor':''}
    collector=Collector.__new__(Collector);collector.store=store
    with store.transaction():collector.accept_chunk('wazuh-archive','wazuh-archives',chunk(raw[:70],0))
    assert store.db.execute('SELECT confirmed FROM native_inputs').fetchone()[0] is None
    reopened=Store(store.directory);replacement=Collector.__new__(Collector);replacement.store=reopened
    with reopened.transaction():replacement.accept_chunk('wazuh-archive','wazuh-archives',chunk(raw[70:],70))
    assert reopened.db.execute('SELECT confirmed FROM native_inputs').fetchone()[0]
    assert reopened.cursor('archive:inode')['buffer']==''
    reopened.db.close()


def test_explicit_quarantine_retry_registers_native_route_without_replacing_raw(store,monkeypatch):
    import xocrange.event_store as event_store
    def unavailable(*args):raise XocError('old_decoder','Previously unsupported input')
    with monkeypatch.context() as patch:
        patch.setattr(event_store,'normalize',unavailable)
        ref,raw=ingest(store)
    assert not pending(store)
    assert store.retry('suricata')['recovered']==1
    assert len(pending(store))==1
    assert store.db.execute('SELECT raw,error FROM records WHERE ref=?',(ref,)).fetchone()[:]==(raw,None)
    assert store.retry('suricata')['recovered']==0 and len(pending(store))==1


def test_apache_empty_request_receipt_preserves_raw_and_can_recover(store):
    raw=b'192.0.2.10 - - [07/Nov/2026:13:00:00 +0000] "-" 408 0 xoc_id=-\n'
    ref,_=ingest(store,'apache-access',raw);frame,=pending(store)
    assert frame['payload']==raw.decode().strip()
    with store.transaction():confirm(store,receipt(frame,''))
    assert store.db.execute('SELECT error FROM native_inputs').fetchone()[0]=='native_decoder_missing'
    with store.transaction():confirm(store,receipt(frame,'xoc-apache-empty-request'))
    with store.transaction():confirm(store,receipt(frame,''))
    assert store.db.execute('SELECT confirmed,error FROM native_inputs').fetchone()[0]
    assert store.db.execute('SELECT error FROM native_inputs').fetchone()[0] is None
    assert store.db.execute('SELECT raw FROM records WHERE ref=?',(ref,)).fetchone()[0]==raw
