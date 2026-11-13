import base64
from dataclasses import replace
import json
from pathlib import Path
import subprocess

import pytest

from xocrange.collector import Collector, read_snapshots, framed
from xocrange.documents import canonical, validate
from xocrange.errors import XocError
from xocrange.events import Context, normalize, SOURCES
from xocrange.event_store import Store

FIXTURES = Path(__file__).parent / 'fixtures/events'
CTX = Context('community', 'local', 'test-source', 'fixture:1', '2026-11-07T13:00:00Z')


@pytest.mark.parametrize('source,name', [
    ('nftables','nftables-drop.log'), ('suricata','suricata-alert.json'),
    ('modsecurity','modsecurity-audit.json'), ('osquery','osquery-results.json'),
    ('sysmon','sysmon-process.xml'), ('auditd','auditd-exec.log'),
    ('apache-access','apache-access.json'), ('apache-error','apache-error.log')])
def test_all_sources_have_searchable_metadata_and_replay_identity(source, name):
    raw = (FIXTURES / name).read_bytes()
    events = normalize(source, raw, CTX)
    assert events and all(e['producer'] == source for e in events)
    assert [e['event_id'] for e in events] == [e['event_id'] for e in normalize(source, raw, replace(CTX, observed_at='2026-11-08T00:00:00Z'))]
    assert all(e['schema_version'] == 'xoc.event/0.2.0' for e in events)
    assert 'DO-NOT-EXPORT' not in json.dumps(events)


def test_osquery_batch_snapshot_empty_and_sensitive_columns():
    data = json.loads((FIXTURES/'osquery-results.json').read_text())
    base = {k:v for k,v in data.items() if k not in ('columns','action')}
    events = normalize('osquery', canonical(base | {'diffResults': {'added':[data['columns']], 'removed':[data['columns']]}}), CTX)
    assert [e['event']['action'] for e in events] == ['added','removed']
    assert events[0]['process']['pid'] == 42
    event, = normalize('osquery', canonical(base | {'snapshot': []}), CTX)
    assert event['osquery']['row_count'] == 0
    with pytest.raises(XocError):
        normalize('osquery', canonical(base | {'snapshot': [{}]*257}), CTX)


def test_sysmon_provider_namespace_network_and_xml_safety():
    raw = (FIXTURES/'sysmon-process.xml').read_bytes()
    e, = normalize('sysmon', raw, CTX)
    assert e['process']['pid'] == 42 and e['sysmon']['event_id'] == 1
    nanoseconds = raw.replace(b'.000000Z', b'.123456789Z')
    assert normalize('sysmon', nanoseconds, CTX)[0]['timestamp'].endswith('.123456Z')
    assert e['event']['outcome'] == 'observed'
    assert normalize('sysmon', raw.replace(b'Linux-Sysmon', b'Microsoft-Windows-Sysmon'), CTX)
    for invalid in (raw.replace(b'Linux-Sysmon', b'Fake-Sysmon'), b'<!DOCTYPE x>'+raw,
                    raw.replace(b'<Data Name="Image">', b'<Data Name="ProcessId">')):
        with pytest.raises(XocError):
            normalize('sysmon', invalid, CTX)


def test_audit_groups_are_one_event_and_incomplete_is_explicit():
    raw = (FIXTURES/'auditd-exec.log').read_bytes()
    e, = normalize('auditd', raw, CTX)
    assert e['audit']['complete'] and e['process']['executable'] == '/usr/bin/true'
    assert e['event']['outcome'] == 'success'
    assert not normalize('auditd', b'\n'.join(raw.splitlines()[:-1]), CTX)[0]['audit']['complete']
    with pytest.raises(XocError):
        normalize('auditd', raw.replace(b'type=EOE msg=audit(1794056400.125:42)', b'type=EOE msg=audit(1794056400.125:43)'), CTX)


def test_audit_enriched_separator_and_sysmon_startup_diagnostics():
    raw = b'type=SERVICE_START msg=audit(1794056400.125:42): pid=1 uid=0 msg="unit=test res=success"\x1dUID="root"\n'
    event, = normalize('auditd', raw, CTX)
    assert event['audit']['record_types'] == ['SERVICE_START']
    event, = normalize('sysmon', b'Sysmon v1.6.0 - Monitors system events', CTX)
    assert event['event']['type'] == 'diagnostic' and 'sysmon' not in event


def test_sysmon_stop_and_loss_diagnostics_are_not_process_observations():
    for raw in (b'Stopping....', b'Total events: 89326, bad events: 0, ratio = 0.000000', b'Lost events: 0, in 0 notifications'):
        event, = normalize('sysmon', raw, CTX)
        assert event['event']['type'] == 'diagnostic' and event['event']['severity'] == 0
    event, = normalize('sysmon', b'Lost events: 5, in 1 notifications', CTX)
    assert event['event']['action'] == 'agent-loss' and event['event']['severity'] == 65


def test_sysmon_start_failure_is_a_sensor_failure_not_quarantined_input():
    # Seen when the eBPF perf ring buffer could not be allocated (order-6 ENOMEM).
    for raw in (b'libbpf: failed to mmap perf buffer on cpu #1: -ENOMEM',
                b'Telemetry failed to start: perf ring buffer could not be started'):
        event, = normalize('sysmon', raw, CTX)
        assert event['event']['type'] == 'diagnostic' and event['event']['action'] == 'agent-failure'
        assert event['event']['severity'] == 65 and 'sysmon' not in event


def test_apache_403_is_failure_not_security_block_and_error_is_diagnostic():
    e, = normalize('apache-access', b'192.0.2.1 - - [07/Nov/2026:13:00:00 +0000] "GET /?token=DO-NOT-EXPORT HTTP/1.1" 403 12', CTX)
    assert e['event']['outcome'] == 'failure' and e['http']['status_code'] == 403
    assert 'DO-NOT-EXPORT' not in json.dumps(e)
    e, = normalize('apache-error', (FIXTURES/'apache-error.log').read_bytes(), CTX)
    assert e['time_basis'] == 'observed' and e['log']['code'] == 'AH00126'


@pytest.mark.parametrize('source', SOURCES)
def test_bad_input_is_quarantined_for_every_source(tmp_path, source):
    store = Store(tmp_path/'store')
    with store.transaction():
        store.ingest(source, 'trusted', 'position-1', b'not-an-event')
    assert store.status()['quarantined'] == 1
    assert not store.pending()


def test_store_atomic_cursor_duplicate_evidence_and_decoding_ack(tmp_path):
    store = Store(tmp_path/'store')
    raw = (FIXTURES/'suricata-alert.json').read_bytes()
    with pytest.raises(RuntimeError):
        with store.transaction():
            store.ingest('suricata','ips','offset-1',raw)
            store.set_cursor('ips', {'offset':1})
            raise RuntimeError('interrupted')
    assert store.cursor('ips') is None and not store.pending()
    with store.transaction():
        ref = store.ingest('suricata','ips','offset-1',raw)
        store.ingest('suricata','ips','offset-1',raw)
    assert len(store.pending()) == 1 and not store.query(confirmed=True)
    e = store.query()[0]['event']
    with store.transaction():
        store.confirm({'agent':{'id':'000'},'location':'xoc-c1','data':e, 'rule':{'id':'110020'}})
    assert len(store.query(confirmed=True)) == 1 and not store.pending()
    assert store.db.execute('SELECT raw FROM records WHERE ref=?',(ref,)).fetchone()[0] == raw
    with pytest.raises(XocError):
        with store.transaction():
            store.ingest('suricata','ips','offset-1',raw+b'\n')
    store.db.close()
    assert len(Store(tmp_path/'store').query(confirmed=True)) == 1


def test_framing_split_json_braces_in_string_and_partial_tail():
    raw = b'\n{\n"a": "}\\\"", "b": []\n}\n{"partial":'
    frames = list(framed(raw, True))
    assert len(frames) == 1 and json.loads(frames[0][2])['b'] == []
    assert raw[frames[0][1]:].strip() == b'{"partial":'


def test_partial_record_survives_collector_restart_and_retry_preserves_evidence(tmp_path):
    raw = (FIXTURES/'modsecurity-audit.json').read_bytes()
    collector = Collector.__new__(Collector); collector.store = Store(tmp_path/'store')
    def chunk(data, offset):
        return {'key':'web:inode-1', 'offset':offset, 'reset':False, 'data':base64.b64encode(data).decode(), 'anchor':''}
    with collector.store.transaction():
        collector.accept_chunk('modsecurity','web',chunk(raw[:30],0))
    assert not collector.store.query()
    collector.store.db.close()
    collector.store = Store(tmp_path/'store')
    with collector.store.transaction():
        collector.accept_chunk('modsecurity','web',chunk(raw[30:],30))
    assert len(collector.store.query()) == 3
    ref = collector.store.query()[0]['event']['evidence']['ref']
    with collector.store.db:
        collector.store.db.execute('DELETE FROM events')
        collector.store.db.execute('UPDATE records SET error=?',('old_decoder',))
    assert collector.store.retry() == {'examined':1,'recovered':1}
    assert collector.store.query()[0]['event']['evidence']['ref'] == ref


def test_audit_interleaving_correlates_by_serial(tmp_path):
    collector = Collector.__new__(Collector); collector.store = Store(tmp_path/'store')
    lines = (FIXTURES/'auditd-exec.log').read_bytes().splitlines(keepends=True)
    with collector.store.transaction():
        for i,line in enumerate(lines):
            collector.accept_audit_line('audit',f'A:{i}',line)
            collector.accept_audit_line('audit',f'B:{i}',line.replace(b':42)',b':43)'))
    events = collector.store.query()
    assert len(events) == 2 and {r['event']['audit']['serial'] for r in events} == {'42','43'}
    assert all(r['event']['audit']['complete'] for r in events)


def test_file_reader_rename_and_copytruncate(tmp_path):
    path = tmp_path/'events.log'; path.write_bytes(b'first\nsecond\n')
    def read(states):
        return read_snapshots(str(path), 'source', states)
    first, = read({})
    state = {first['key']:{'offset':13,'anchor':first['anchor']}}
    path.rename(tmp_path/'events.log.1'); path.write_bytes(b'new\n')
    old, new = read(state)
    assert old['key'] == first['key'] and not base64.b64decode(old['data'])
    assert base64.b64decode(new['data']) == b'new\n'
    path.write_bytes(b'n\n')
    state[new['key']] = {'offset':4, 'anchor':new['anchor']}
    assert read(state)[1]['reset'] is True


def test_v01_validation_remains_available():
    e = normalize('suricata', (FIXTURES/'suricata-alert.json').read_bytes(), CTX)[0]
    validate(e | {'schema_version':'xoc.event/0.1.0'}, 'c1-event')
    with pytest.raises(XocError):
        validate(e | {'schema_version':'xoc.event/0.1.0','producer':'sysmon'}, 'c1-event')


def test_large_and_binary_journal_messages_do_not_stall_collection(tmp_path,monkeypatch):
    import io
    import time
    collector=Collector.__new__(Collector);collector.store=Store(tmp_path/'store')
    raw=(FIXTURES/'sysmon-process.xml').read_text()
    large=raw.replace('DO-NOT-EXPORT','x'*5000)
    messages=[large,list(raw.encode()),None,[255,254],raw]
    rows=[{'MESSAGE':message,'__CURSOR':str(i),'__REALTIME_TIMESTAMP':str(int(time.time()*1000000))} for i,message in enumerate(messages)]
    class Process:
        def __init__(self,args,**kwargs):
            assert '--all' in args
            self.stdout=io.BytesIO(('\n'.join(json.dumps(row) for row in rows)+'\n').encode())
        def wait(self,**kwargs):return 0
        def poll(self):return 0
    monkeypatch.setattr('xocrange.collector.subprocess.Popen',Process)
    assert collector.sysmon()=='ready'
    assert collector.store.cursor('sysmon-journal')['cursor']=='4'
    assert collector.store.status()['quarantined']==2
    assert collector.store.db.execute('SELECT COUNT(*) FROM records WHERE raw=?',(b'\xff\xfe',)).fetchone()[0]==1
    assert len(collector.store.query())==3


def test_journal_batch_and_cursor_roll_back_together(tmp_path,monkeypatch):
    import io
    import time
    collector=Collector.__new__(Collector);collector.store=Store(tmp_path/'store')
    raw=(FIXTURES/'sysmon-process.xml').read_text()
    rows=[{'MESSAGE':raw,'__CURSOR':'one','__REALTIME_TIMESTAMP':str(int(time.time()*1000000))},
          {'MESSAGE':raw,'__REALTIME_TIMESTAMP':str(int(time.time()*1000000))}]
    class Process:
        def __init__(self,*args,**kwargs):self.stdout=io.BytesIO(('\n'.join(json.dumps(row) for row in rows)+'\n').encode())
        def wait(self,**kwargs):return 0
        def poll(self):return 0
    monkeypatch.setattr('xocrange.collector.subprocess.Popen',Process)
    with pytest.raises(XocError) as error:collector.sysmon()
    assert error.value.code=='journal_format'
    assert collector.store.cursor('sysmon-journal') is None
    assert collector.store.db.execute('SELECT COUNT(*) FROM records').fetchone()[0]==0
