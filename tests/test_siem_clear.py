import json
from types import SimpleNamespace

import pytest

from xocrange import operations as ops
from xocrange import siem_clear
from xocrange.collector import read_snapshots
from xocrange.event_store import Store
from xocrange.log_maintenance import history


def volumes(tmp_path):
    result = {}
    for name in ('fw-logs', 'ips-logs', 'web-logs', 'siem-logs'):
        result[name] = tmp_path / name
        result[name].mkdir()
    return result


def test_device_logs_truncated_in_place_and_rotations_removed(tmp_path):
    v = volumes(tmp_path)
    (v['fw-logs'] / 'events.log.xoc-01700000000000000000').write_bytes(b'old generation\n')
    (v['ips-logs'] / 'eve.json').write_bytes(b'{"old":1}\n')
    (v['web-logs'] / 'error.log').write_bytes(b'old error\n')
    (v['web-logs'] / 'unrelated.conf').write_bytes(b'keep\n')
    # A running writer keeps appending through its open descriptor after the clear.
    writer = open(v['fw-logs'] / 'events.log', 'a')
    writer.write('old line\n'); writer.flush()
    report = siem_clear.clear_device_logs(v)
    writer.write('new line\n'); writer.flush(); writer.close()
    assert (v['fw-logs'] / 'events.log').read_bytes() == b'new line\n'
    assert (v['ips-logs'] / 'eve.json').read_bytes() == b''
    assert not (v['fw-logs'] / 'events.log.xoc-01700000000000000000').exists()
    assert (v['web-logs'] / 'unrelated.conf').read_bytes() == b'keep\n'
    assert report['truncated'] == 3 and report['removed'] == 1 and report['skipped'] == []


def test_planted_links_never_redirect_a_root_truncate_or_unlink(tmp_path):
    v = volumes(tmp_path)
    host = tmp_path / 'host-secret'; host.write_bytes(b'host data\n')
    (v['web-logs'] / 'access.log').symlink_to(host)
    (v['fw-logs'] / 'events.log.xoc-01700000000000000000').symlink_to(host)
    (v['siem-logs'] / 'alerts').symlink_to(tmp_path)
    (v['siem-logs'] / 'archives').mkdir()
    (v['siem-logs'] / 'archives' / '2026').symlink_to(tmp_path)
    devices = siem_clear.clear_device_logs(v)
    manager = siem_clear.clear_manager_logs(v)
    assert host.read_bytes() == b'host data\n'
    assert sorted(devices['skipped']) == ['access.log', 'events.log.xoc-01700000000000000000']
    assert manager['skipped'] == ['alerts', 'archives/2026']


def test_manager_alerts_and_dated_generations_cleared(tmp_path):
    v = volumes(tmp_path)
    for kind, stem in (('alerts', 'ossec-alerts-'), ('archives', 'ossec-archive-')):
        month = v['siem-logs'] / kind / '2026' / 'Nov'
        month.mkdir(parents=True)
        (v['siem-logs'] / kind / (kind + '.json')).write_bytes(b'{"a":1}\n')
        (month / (stem + '12.json.gz')).write_bytes(b'x')
        (month / (stem + '12.log.gz')).write_bytes(b'x')
    (v['siem-logs'] / 'ossec.log').write_bytes(b'manager operations\n')
    report = siem_clear.clear_manager_logs(v)
    assert (v['siem-logs'] / 'alerts' / 'alerts.json').read_bytes() == b''
    assert list((v['siem-logs'] / 'alerts' / '2026' / 'Nov').iterdir()) == []
    assert (v['siem-logs'] / 'ossec.log').read_bytes() == b'manager operations\n'
    assert report['truncated'] == 2 and report['removed'] == 4


def test_store_reset_keeps_installer_cursors_and_resumes_host_logs_at_their_end(tmp_path):
    directory = tmp_path / 'siem'
    store = Store(directory)
    with store.transaction():
        store.ingest('apache-access', 'web-access', 'p1', b'10.0.0.1 - - [13/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1\n')
        store.set_cursor('indexer-mapping', 'digest')
        store.set_cursor('native-rules-revision', 'rev')
        store.set_cursor('sysmon-journal', {'cursor': 'old', 'source_time': 1})
        store.set_cursor('web-access:xoc_web-logs:1:2', {'offset': 99})
    store.db.close()
    audit = tmp_path / 'audit.log'
    audit.write_bytes(b'type=OLD msg=audit(1.0:1): before the clear\n')
    (tmp_path / 'audit.log.1').write_bytes(b'type=OLD msg=audit(0.5:1): older generation\n')
    siem_clear.reset_store(directory, [('host-auditd', str(audit))])
    store = Store(directory)
    assert store.db.execute('SELECT COUNT(*) FROM records').fetchone()[0] == 0
    assert store.cursor('indexer-mapping') == 'digest' and store.cursor('native-rules-revision') == 'rev'
    assert store.cursor('sysmon-journal') is None and store.cursor('sysmon-journal-resume')['since'] > 0
    assert store.cursor('web-access:xoc_web-logs:1:2') is None
    # The collector's next read of the host log yields only lines written after the clear.
    with audit.open('ab') as stream:
        stream.write(b'type=NEW msg=audit(2.0:2): after the clear\n')
    owner = 'host-auditd:host'
    states = {row[0]: json.loads(row[1]) for row in store.db.execute('SELECT name,value FROM cursors WHERE name LIKE ?', (owner + ':%',))}
    chunks = read_snapshots(str(audit), owner, states, history=history(str(audit)))
    import base64
    data = b''.join(base64.b64decode(c['data']) for c in chunks)
    assert data == b'type=NEW msg=audit(2.0:2): after the clear\n'
    assert not any(c['reset'] for c in chunks)


def test_only_siem_indices_are_deleted():
    calls = []

    class Client:
        def request(self, method, path):
            calls.append((method, path))
            if method == 'GET':
                return 200, [{'index': 'xoc-events-2026.11.13'}, {'index': 'wazuh-alerts-4.x-2026.11.13'},
                             {'index': 'wazuh-monitoring-2026.11.13'}, {'index': '.opendistro_security'}]
            return 200, {}
    assert siem_clear.delete_indices(Client()) == 2
    assert [p for m, p in calls if m == 'DELETE'] == ['/xoc-events-2026.11.13', '/wazuh-alerts-4.x-2026.11.13']


@pytest.fixture
def appliance(tmp_path, monkeypatch):
    v = volumes(tmp_path)
    (v['web-logs'] / 'access.log').write_bytes(b'old request\n')
    calls = []
    monkeypatch.setattr(ops, 'installed', lambda: {'selected': ['siem', 'security-path'], 'release': str(tmp_path), 'plan': 'p'})
    monkeypatch.setattr(ops, 'volume_paths', lambda: v)
    monkeypatch.setattr(ops, 'command', lambda args, **k: calls.append(list(args)) or SimpleNamespace(returncode=0))
    monkeypatch.setattr('xocrange.collector.FILES', ())
    directory = tmp_path / 'siem'
    store = Store(directory)
    with store.transaction():
        store.ingest('apache-access', 'web-access', 'p1', b'10.0.0.1 - - [13/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1\n')
    store.db.close()
    return SimpleNamespace(volumes=v, calls=calls, directory=directory)


def test_clear_without_confirmation_changes_nothing(appliance):
    result = siem_clear.clear(appliance.directory, confirmed=False)
    assert result['status'] == 'confirmation-required' and result['device_log_bytes'] == len(b'old request\n')
    assert appliance.calls == []
    assert (appliance.volumes['web-logs'] / 'access.log').read_bytes() == b'old request\n'
    assert Store(appliance.directory).db.execute('SELECT COUNT(*) FROM records').fetchone()[0] == 1


def test_clear_stops_the_collector_for_the_whole_reset(appliance):
    result = siem_clear.clear(appliance.directory, confirmed=True)
    assert result['status'] == 'cleared' and result['collector'] == 'restarted'
    assert [c[1] for c in appliance.calls] == ['is-active', 'stop', 'start']
    assert (appliance.volumes['web-logs'] / 'access.log').read_bytes() == b''
    assert Store(appliance.directory).db.execute('SELECT COUNT(*) FROM records').fetchone()[0] == 0


def test_cli_exposes_clear_with_explicit_confirmation():
    from xocrange.cli import parser
    args = parser().parse_args(['siem', 'clear', '--yes'])
    assert args.action == 'clear' and args.yes
    assert not parser().parse_args(['siem', 'clear']).yes
