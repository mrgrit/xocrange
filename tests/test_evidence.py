"""ADR-0008 evidence queries: closed checks over recorded evidence, references not scores."""
import json
import os
from pathlib import Path
import socket

import pytest

from xocrange.errors import XocError
from xocrange.event_store import Store
from xocrange.evidence import QUERY, Sources, evaluate, read_bounded

WINDOW = {'since': '2026-11-14T00:00:00.000000Z', 'until': '2026-11-14T01:00:00.000000Z'}
ATTACKER = '10.20.30.9'


def suricata(src, sid, ts='2026-11-14T00:10:00.000000+0000'):
    return json.dumps({'timestamp': ts, 'event_type': 'alert', 'src_ip': src, 'src_port': 40000, 'dest_ip': '10.20.32.80',
                       'dest_port': 80, 'proto': 'TCP', 'alert': {'signature_id': sid, 'severity': 2, 'action': 'allowed',
                                                                   'signature': f'xoc-web-01 probe {sid}'}}).encode()


@pytest.fixture
def sources(tmp_path):
    store = Store(tmp_path / 'siem')
    store.ingest('suricata', 'ips-eve', 1, suricata(ATTACKER, 9100001), observed='2026-11-14T00:10:01.000000Z')
    store.ingest('suricata', 'ips-eve', 2, suricata('10.20.30.50', 9100002), observed='2026-11-14T00:11:01.000000Z')
    store.ingest('suricata', 'ips-eve', 3, suricata(ATTACKER, 9100003), observed='2026-11-14T03:00:00.000000Z')
    alert = {'rule': {'id': '100201', 'level': 10, 'groups': ['xoc', 'web_attack']}, 'full_log': 'xoc-web-01 marker'}
    raw = json.dumps(alert).encode()
    # Real stores keep the alert in `raw` with an empty `document` (verified on an installed Core).
    store.db.execute('INSERT INTO wazuh_alerts(id, observed, raw, sha256, document) VALUES (?,?,?,?,?)',
                     ('a1', '2026-11-14T00:12:00.000000Z', raw, 'f' * 64, ''))
    store.db.execute('INSERT INTO wazuh_alerts(id, observed, raw, sha256, document) VALUES (?,?,?,?,?)',
                     ('a2', '2026-11-14T00:13:00.000000Z', b'not json', 'e' * 64, ''))
    store.db.commit()
    policy = tmp_path / 'ips-policy'; policy.mkdir()
    (policy / 'current.conf').write_text('alert http any any -> any any (msg:"xoc"; sid:9100001;)\n')
    root = tmp_path / 'web-root'; (root / 'tmp').mkdir(parents=True)
    (root / 'tmp' / 'shell.php').write_text('<?php echo "pwned"; ?>')
    os.symlink('/etc/hostname', root / 'tmp' / 'link')
    return Sources(tmp_path / 'siem' / 'events.sqlite3', policy={'ips': policy},
                   processes=lambda service: ['apache2', 'apache2'] if service == 'web' else [])


def query(*checks, **extra):
    return {'schema_version': QUERY, 'request_id': 'r1', 'window': WINDOW, 'attacker_ips': [ATTACKER],
            'checks': [dict(id=f'c{i}', **c) for i, c in enumerate(checks)], **extra}


def results(sources, *checks, **extra):
    return [(r['result'], r['count']) for r in evaluate(sources, query(*checks, **extra))['results']]


def test_c1_events_filter_by_producer_window_field_and_attacker(sources):
    assert results(sources,
                   {'type': 'c1_event', 'target': 'siem', 'params': {'producer': 'suricata'}},
                   {'type': 'c1_event', 'target': 'siem', 'params': {'producer': 'suricata', 'source_is_attacker': True}},
                   {'type': 'c1_event', 'target': 'siem', 'params': {'producer': 'suricata', 'where': {'rule.id': '9100002'}}},
                   {'type': 'c1_event', 'target': 'siem', 'params': {'producer': 'suricata', 'min_count': 3}},
                   {'type': 'c1_event', 'target': 'siem', 'params': {'producer': 'modsecurity'}}) == [
        ('passed', 2), ('passed', 1), ('passed', 1), ('failed', 2), ('failed', 0)]


def test_evidence_references_and_parameter_hash(sources):
    out = evaluate(sources, query({'type': 'c1_event', 'target': 'siem', 'params': {'producer': 'suricata', 'source_is_attacker': True}}))
    result = out['results'][0]
    assert result['evidence'][0]['ref'].startswith('c1:') and len(result['evidence'][0]['sha256']) == 64
    assert len(result['params_sha256']) == 64 and 'score' not in json.dumps(out)


def test_wazuh_alerts_by_rule_group_level_and_literal(sources):
    assert results(sources,
                   {'type': 'wazuh_alert', 'target': 'siem', 'params': {'rule_id': '100201'}},
                   {'type': 'wazuh_alert', 'target': 'siem', 'params': {'groups': ['web_attack'], 'min_level': 10}},
                   {'type': 'wazuh_alert', 'target': 'siem', 'params': {'pattern': 'xoc-web-01'}},
                   {'type': 'wazuh_alert', 'target': 'siem', 'params': {'groups': ['authentication_failed']}},
                   {'type': 'wazuh_alert', 'target': 'siem', 'params': {'pattern': '%'}}) == [
        ('passed', 1), ('passed', 1), ('passed', 1), ('failed', 0), ('failed', 0)]


def test_raw_device_records_must_match_the_device(sources):
    assert results(sources,
                   {'type': 'log_contains', 'target': 'ips', 'params': {'log': 'suricata', 'pattern': 'probe 9100002'}},
                   {'type': 'log_contains', 'target': 'web', 'params': {'log': 'suricata', 'pattern': 'probe'}}) == [
        ('passed', 1), ('inconclusive', 0)]


def test_applied_device_policy(sources):
    assert results(sources,
                   {'type': 'device_config', 'target': 'ips', 'params': {'contains': 'sid:9100001'}},
                   {'type': 'device_config', 'target': 'ips', 'params': {'absent': 'sid:9100001'}},
                   {'type': 'device_config', 'target': 'fw', 'params': {'contains': 'x'}}) == [
        ('passed', 1), ('failed', 0), ('inconclusive', 0)]


def test_service_state_ports_and_processes(sources):
    listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen()
    port = listener.getsockname()[1]
    sources.pid = lambda service: os.getpid() if service == 'web' else None
    try:
        assert results(sources,
                       {'type': 'port_listening', 'target': 'web', 'params': {'port': port}},
                       {'type': 'port_listening', 'target': 'web', 'params': {'port': 1}},
                       {'type': 'port_listening', 'target': 'juice', 'params': {'port': port}},
                       {'type': 'process_running', 'target': 'web', 'params': {'name': 'apache2'}},
                       {'type': 'process_running', 'target': 'web', 'params': {'name': 'nc'}}) == [
            ('passed', 1), ('failed', 0), ('inconclusive', 0), ('passed', 2), ('failed', 0)]
    finally:
        listener.close()


def test_files_only_in_allowed_locations_without_links(sources, tmp_path):
    root = tmp_path / 'web-root'
    assert read_bounded(root, 'tmp/shell.php').startswith(b'<?php')
    with pytest.raises(XocError):
        read_bounded(root, 'tmp/link')
    with pytest.raises(XocError):
        read_bounded(root, 'tmp/../etc/passwd')
    (root / 'tmp' / 'big').write_bytes(b'x' * (256 * 1024 + 1))
    with pytest.raises(XocError):
        read_bounded(root, 'tmp/big')
    # /proc/<pid>/root of this test process: the allow-list is checked before any read.
    sources.pid = lambda service: os.getpid()
    assert results(sources, {'type': 'file_exists', 'target': 'web', 'params': {'path': '/etc/passwd'}}) == [('inconclusive', 0)]


@pytest.mark.parametrize('check', [
    {'type': 'process_running', 'target': 'web', 'params': {'name': 'apache2; id'}},
    {'type': 'c1_event', 'target': 'siem', 'params': {'producer': 'suricata', 'where': {"event') OR 1=1 --": 'x'}}},
    {'type': 'file_contains', 'target': 'web', 'params': {'path': '/tmp/../etc/shadow', 'pattern': 'root'}},
    {'type': 'command_ran', 'target': 'attacker', 'params': {'pattern': 'nmap'}},
])
def test_unsafe_queries_are_rejected_before_evaluation(sources, check):
    with pytest.raises(XocError):
        evaluate(sources, query(check))


def test_missing_store_is_reported(tmp_path):
    with pytest.raises(XocError):
        evaluate(Sources(tmp_path / 'none.sqlite3'), query({'type': 'wazuh_alert', 'target': 'siem', 'params': {'rule_id': '1'}}))


def test_socket_handler_answers_only_the_module_uid(sources, tmp_path, monkeypatch):
    import xocrange.evidence as ev
    monkeypatch.setattr(ev, 'AUDIT', tmp_path / 'audit.jsonl')
    request = json.dumps(query({'type': 'wazuh_alert', 'target': 'siem', 'params': {'rule_id': '100201'}})).encode() + b'\n'
    for uid, ok in ((os.getuid(), True), (os.getuid() + 1, False)):
        server, client = socket.socketpair()
        client.sendall(request)
        ev.handle(server, 'M15', uid, sources)
        answer = json.loads(client.recv(1 << 20))
        client.close()
        assert ('results' in answer) is ok and (answer.get('error') == 'peer_not_allowed') is (not ok)
    lines = [json.loads(l) for l in (tmp_path / 'audit.jsonl').read_text().splitlines()]
    assert [l.get('error') for l in lines] == [None, 'peer_not_allowed']
    assert lines[0]['checks'][0]['params_sha256'] and lines[0]['results'][0]['result'] == 'passed'
    assert '100201' not in json.dumps(lines)  # parameters are hashed, not logged


def test_socket_handler_rejects_garbage(sources, tmp_path, monkeypatch):
    import xocrange.evidence as ev
    monkeypatch.setattr(ev, 'AUDIT', tmp_path / 'audit.jsonl')
    server, client = socket.socketpair()
    client.sendall(b'{"schema_version": "xoc.evidence-query/0.1.0", "checks": "rm -rf /"}\n')
    ev.handle(server, 'M15', os.getuid(), sources)
    assert json.loads(client.recv(65536)) == {'error': 'schema_violation'}


def test_socket_handler_answers_internal_errors(sources, tmp_path, monkeypatch):
    import xocrange.evidence as ev
    monkeypatch.setattr(ev, 'AUDIT', tmp_path / 'audit.jsonl')
    def broken(*args, **kwargs):
        import sqlite3
        raise sqlite3.OperationalError('malformed JSON')
    monkeypatch.setattr(ev, 'evaluate', broken)
    server, client = socket.socketpair()
    client.sendall(json.dumps(query({'type': 'wazuh_alert', 'target': 'siem', 'params': {'rule_id': '1'}})).encode() + b'\n')
    ev.handle(server, 'M15', os.getuid(), sources)
    assert json.loads(client.recv(65536)) == {'error': 'internal_error'}


def test_only_range_services_can_be_inspected(sources):
    sources.pid = lambda service: os.getpid()
    sources.processes = lambda service: ['python3']
    for target in ('siem', 'platform', 'indexer', 'm15-assessor'):
        assert results(sources,
                       {'type': 'file_exists', 'target': target, 'params': {'path': '/tmp/x'}},
                       {'type': 'process_running', 'target': target, 'params': {'name': 'python3'}},
                       {'type': 'port_listening', 'target': target, 'params': {'port': 22}}) == [('inconclusive', 0)] * 3


def test_evidence_carries_bounded_excerpts_for_instructors(sources):
    out = evaluate(sources, query({'type': 'wazuh_alert', 'target': 'siem', 'params': {'pattern': 'xoc-web-01'}},
                                  {'type': 'c1_event', 'target': 'siem', 'params': {'producer': 'suricata', 'source_is_attacker': True}}))
    alert, event = (r['evidence'][0] for r in out['results'])
    assert alert['excerpt'] == 'rule 100201 L10 : xoc-web-01 marker'
    assert ATTACKER in event['excerpt'] and 'xoc-evidence' not in event['excerpt']
    assert all(len(e['excerpt']) <= 1000 for r in out['results'] for e in r['evidence'])
