"""Read-only evidence queries for entitled commercial modules (ADR-0008).

Core answers closed, literal questions about what it recorded (C1 events, raw
device records, Wazuh alerts, applied device policy, service state, files in
allowed locations) and returns facts with evidence references. It never scores.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat

from .documents import validate
from .errors import XocError

QUERY = 'xoc.evidence-query/0.1.0'
RESULT = 'xoc.evidence-result/0.1.0'
MAX_EVIDENCE = 16
MAX_FILE = 256 * 1024
MAX_SCAN = 20000
# Raw device record sources by Assessor log name (collector FILES).
LOG_SOURCES = {'nftables': 'nftables', 'suricata': 'suricata', 'modsec': 'modsecurity',
               'apache-access': 'apache-access', 'apache-error': 'apache-error'}
LOG_SERVICE = {'nftables': 'fw', 'suricata': 'ips', 'modsec': 'web', 'apache-access': 'web', 'apache-error': 'web'}
# Applied device policy written by the console brokers (planner console-*-state volumes).
POLICY_FILES = {'fw': 'current.conf', 'ips': 'current.conf', 'waf': 'current.conf'}
# Files may be read only below these prefixes; device configuration is device_config.
FILE_PREFIXES = ('/tmp/', '/var/tmp/', '/dev/shm/', '/var/www/html/')


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def params_sha256(params) -> str:
    return hashlib.sha256(canonical(params)).hexdigest()


def stamp(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def parse(value: str) -> datetime:
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


class Sources:
    """Where evidence lives. Production wiring is in `host_sources`; tests pass fakes."""

    def __init__(self, store: Path, policy: dict | None = None, pid=None, processes=None, now=None):
        self.store = Path(store)
        self.policy = policy or {}            # device -> directory holding current.conf
        self.pid = pid or (lambda service: None)            # service -> host pid of its main process
        self.processes = processes or (lambda service: [])  # service -> process names
        self.now = now or (lambda: datetime.now(timezone.utc))

    def database(self):
        if not self.store.is_file():
            raise XocError('evidence_unavailable', 'The SIEM evidence store is not available.')
        return sqlite3.connect(f'file:{self.store}?mode=ro', uri=True, timeout=10)


class Evaluator:
    def __init__(self, sources: Sources, request: dict):
        self.sources = sources
        self.request = request
        self.attackers = set(request.get('attacker_ips') or [])

    def window(self, params):
        window = self.request.get('window')
        if window:
            return window['since'], window['until']
        until = self.sources.now()
        return stamp(until - timedelta(seconds=params.get('since_sec', 3600))), stamp(until)

    def run(self) -> dict:
        results = []
        with self.sources.database() as db:
            self.db = db
            for check in self.request['checks']:
                try:
                    passed, count, evidence, reason = getattr(self, 'check_' + check['type'])(check)
                    result = 'passed' if passed else 'failed'
                except XocError as exc:
                    passed, count, evidence, reason, result = False, 0, [], exc.code, 'inconclusive'
                item = {'check_id': check['id'], 'params_sha256': params_sha256(check['params']),
                        'result': result, 'count': count, 'evidence': evidence[:MAX_EVIDENCE]}
                if reason:
                    item['reason'] = reason[:500]
                results.append(item)
        return {'schema_version': RESULT, 'request_id': self.request['request_id'],
                'evaluated_at': stamp(self.sources.now()), 'results': results}

    # ── SIEM store ──────────────────────────────────────────────
    def check_c1_event(self, check):
        p = check['params']
        since, until = self.window(p)
        clauses, args = ['producer=?', 'observed>=?', 'observed<=?'], [p['producer'], since, until]
        for field, value in (p.get('where') or {}).items():
            clauses.append(f"json_extract(event, '$.{field}')=?")
            args.append(value)
        if p.get('contains'):
            clauses.append(f"instr(json_extract(event, '$.{p['contains']['field']}'), ?)>0")
            args.append(p['contains']['value'])
        if p.get('source_is_attacker'):
            if not self.attackers:
                raise XocError('attacker_unknown', 'source_is_attacker needs attacker_ips in the request.')
            clauses.append("json_extract(event, '$.network.source.ip') IN (%s)" % ','.join('?' * len(self.attackers)))
            args.extend(sorted(self.attackers))
        rows = self.db.execute('SELECT id, observed, event FROM events WHERE ' + ' AND '.join(clauses)
                               + ' ORDER BY observed LIMIT ?', (*args, MAX_SCAN)).fetchall()
        evidence = [{'kind': 'c1_event', 'ref': 'c1:' + r[0], 'sha256': hashlib.sha256(r[2].encode()).hexdigest(),
                     'observed_at': r[1]} for r in rows[:MAX_EVIDENCE]]
        return len(rows) >= p.get('min_count', 1), len(rows), evidence, None

    def check_wazuh_alert(self, check):
        p = check['params']
        since, until = self.window(p)
        clauses, args = ['observed>=?', 'observed<=?'], [since, until]
        # The stored alert is `raw` (the search `document` column is empty since K12 storage
        # changes); guard so one malformed record cannot fail the whole query.
        alert = "(CASE WHEN json_valid(CAST(raw AS TEXT)) THEN CAST(raw AS TEXT) END)"
        if 'rule_id' in p:
            clauses.append(f"json_extract({alert}, '$.rule.id')=?"); args.append(p['rule_id'])
        if 'min_level' in p:
            clauses.append(f"CAST(json_extract({alert}, '$.rule.level') AS INTEGER)>=?"); args.append(p['min_level'])
        for group in p.get('groups') or []:
            clauses.append(f"EXISTS (SELECT 1 FROM json_each({alert}, '$.rule.groups') WHERE value=?)"); args.append(group)
        if 'pattern' in p:
            clauses.append('instr(CAST(raw AS TEXT), ?)>0'); args.append(p['pattern'])
        rows = self.db.execute('SELECT id, observed, sha256 FROM wazuh_alerts WHERE ' + ' AND '.join(clauses)
                               + ' ORDER BY observed LIMIT ?', (*args, MAX_SCAN)).fetchall()
        evidence = [{'kind': 'alert', 'ref': 'wazuh:' + r[0], 'sha256': r[2], 'observed_at': r[1]} for r in rows[:MAX_EVIDENCE]]
        return bool(rows), len(rows), evidence, None

    def check_log_contains(self, check):
        p = check['params']
        if LOG_SERVICE[p['log']] != check['target']:
            raise XocError('log_target', 'The log does not belong to the requested device.')
        since, until = self.window(p)
        rows = self.db.execute('SELECT ref, observed, sha256 FROM records WHERE source=? AND observed>=? AND observed<=? '
                               'AND instr(CAST(raw AS TEXT), ?)>0 ORDER BY observed LIMIT ?',
                               (LOG_SOURCES[p['log']], since, until, p['pattern'], MAX_SCAN)).fetchall()
        evidence = [{'kind': 'c1_event', 'ref': r[0], 'sha256': r[2], 'observed_at': r[1]} for r in rows[:MAX_EVIDENCE]]
        return bool(rows), len(rows), evidence, None

    # ── Device policy and service state ─────────────────────────
    def check_device_config(self, check):
        directory = self.sources.policy.get(check['target'])
        if directory is None:
            raise XocError('policy_unavailable', 'The device policy is not managed on this appliance.')
        data = read_bounded(Path(directory), POLICY_FILES.get(check['target'], 'current.conf'))
        text = data.decode('utf-8', 'replace')
        p = check['params']
        passed = p['contains'] in text if 'contains' in p else p['absent'] not in text
        ref = f'policy:{check["target"]}'
        return passed, int(passed), [{'kind': 'device_config', 'ref': ref, 'sha256': hashlib.sha256(data).hexdigest()}], None

    def check_port_listening(self, check):
        pid = self.service_pid(check['target'])
        port, protocol = check['params']['port'], check['params'].get('protocol', 'tcp')
        tables = ('tcp', 'tcp6') if protocol == 'tcp' else ('udp', 'udp6')
        listening = False
        for table in tables:
            path = Path(f'/proc/{pid}/net/{table}')
            if not path.is_file():
                continue
            for line in path.read_text().splitlines()[1:]:
                fields = line.split()
                if len(fields) > 3 and int(fields[1].rsplit(':', 1)[1], 16) == port and (protocol == 'udp' or fields[3] == '0A'):
                    listening = True
        digest = hashlib.sha256(f'{check["target"]}:{protocol}:{port}:{listening}'.encode()).hexdigest()
        return listening, int(listening), [{'kind': 'service_state', 'ref': f'service:{check["target"]}', 'sha256': digest}], None

    def check_process_running(self, check):
        names = self.sources.processes(check['target'])
        running = check['params']['name'] in names
        digest = hashlib.sha256(canonical(sorted(set(names)))).hexdigest()
        return running, names.count(check['params']['name']), [{'kind': 'service_state', 'ref': f'service:{check["target"]}', 'sha256': digest}], None

    def check_file_exists(self, check):
        data = self.container_file(check)
        return data is not None, int(data is not None), self.file_evidence(check, data), None

    def check_file_contains(self, check):
        data = self.container_file(check)
        passed = data is not None and check['params']['pattern'] in data.decode('utf-8', 'replace')
        return passed, int(passed), self.file_evidence(check, data), None

    def check_file_hash(self, check):
        data = self.container_file(check)
        passed = data is not None and hashlib.sha256(data).hexdigest() == check['params']['sha256']
        return passed, int(passed), self.file_evidence(check, data), None

    def service_pid(self, service):
        pid = self.sources.pid(service)
        if not pid:
            raise XocError('service_unavailable', 'The service is not running on this appliance.')
        return pid

    def container_file(self, check):
        path = check['params']['path']
        if not path.startswith(FILE_PREFIXES):
            raise XocError('path_not_allowed', 'Files may be read only from allowed locations.')
        root = Path(f'/proc/{self.service_pid(check["target"])}/root')
        try:
            return read_bounded(root, path.lstrip('/'))
        except FileNotFoundError:
            return None

    @staticmethod
    def file_evidence(check, data):
        if data is None:
            return []
        return [{'kind': 'file', 'ref': f'file:{check["target"]}:{check["params"]["path"]}', 'sha256': hashlib.sha256(data).hexdigest()}]


def read_bounded(base: Path, relative: str) -> bytes:
    """Open base/relative one component at a time without following links."""
    parts = [p for p in relative.split('/') if p]
    if not parts or any(p in ('.', '..') for p in parts):
        raise XocError('path_not_allowed', 'Unexpected path component.')
    fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        try:
            leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
        except OSError as exc:
            if exc.errno == 40:  # ELOOP: a link where a file was expected
                raise XocError('path_not_allowed', 'Links are not followed.') from exc
            raise
        try:
            info = os.fstat(leaf)
            if not stat.S_ISREG(info.st_mode):
                raise XocError('path_not_allowed', 'Only regular files can be read.')
            if info.st_size > MAX_FILE:
                raise XocError('file_too_large', 'The file exceeds the evidence size limit.')
            return os.read(leaf, MAX_FILE + 1)[:MAX_FILE]
        finally:
            os.close(leaf)
    except NotADirectoryError as exc:
        raise FileNotFoundError(relative) from exc
    finally:
        os.close(fd)


def evaluate(sources: Sources, request: dict) -> dict:
    validate(request, 'evidence-query')
    if 'checks' not in request or request.get('schema_version') != QUERY:
        raise XocError('schema_violation', 'Expected an evidence query.')
    return validate(Evaluator(sources, request).run(), 'evidence-query')


# ── Host service (root): one socket per entitled module ─────────────────────
STATE = Path('/var/lib/xocrange')
AUDIT = Path('/var/log/xocrange/evidence.jsonl')
SOCKET_NAME = 'evidence.sock'
CREDENTIAL_FILES = ('range-control.url', 'client.crt', 'client.key', 'ca.crt')
MAX_REQUEST = 512 * 1024


def _installed():
    from .lab import Docker, checked_plan
    install = json.loads((STATE / 'last-install.json').read_text())
    release = Path(install['release'])
    plan_dir, result = checked_plan(release, install['plan'], entitlement_action='read')
    return release, Docker(plan_dir / 'compose.yaml', result['compose']['name']), result


def _volume(engine, project, short):
    info, = json.loads(engine.run(['volume', 'inspect', f'{project}_{short}']))
    labels = info.get('Labels') or {}
    mount = Path(info['Mountpoint'])
    if (labels.get('com.docker.compose.project') != project or labels.get('com.docker.compose.volume') != short
            or info.get('Driver') != 'local' or not mount.is_absolute() or any(p.is_symlink() for p in (mount, *mount.parents))):
        raise XocError('untrusted_volume', 'Volume ownership differs from the validated plan.')
    return mount


def evidence_modules(result):
    """Selected modules entitled to evidence-query: id -> (service names, container uid)."""
    from .planner import EVIDENCE
    modules = {}
    services = result['compose']['services']
    for identifier in result['lock']['selected']:
        owned = [name for name, service in services.items()
                 if f'evidence-{identifier}:/run/xoc-evidence:ro' in service.get('volumes', [])]
        if owned:
            uid = int(str(services[owned[0]]['user']).split(':')[0])
            modules[identifier] = (owned, uid)
    return modules


def host_sources(engine, result):
    project = result['compose']['name']
    policy = {}
    for device in ('fw', 'ips', 'waf'):
        if f'console-{device}-state' in (result['compose'].get('volumes') or {}):
            policy[device] = _volume(engine, project, f'console-{device}-state')

    def container(service):
        ids = engine.run(['ps', '-q', service], compose=True).split()
        return ids[0] if ids else None

    def pid(service):
        if service not in result['compose']['services']:
            return None
        cid = container(service)
        return int(engine.run(['inspect', '--format', '{{.State.Pid}}', cid]).strip() or 0) if cid else None

    def processes(service):
        cid = container(service) if service in result['compose']['services'] else None
        if not cid:
            return []
        # Docker needs a PID column in the ps output (`-eo comm` alone is refused).
        rows = engine.run(['top', cid, '-o', 'pid,comm']).splitlines()[1:]
        return [row.split(None, 1)[1].strip() for row in rows if len(row.split(None, 1)) == 2]

    return Sources(STATE / 'siem' / 'events.sqlite3', policy=policy, pid=pid, processes=processes)


def audit(module, request, response=None, error=None):
    entry = {'at': stamp(datetime.now(timezone.utc)), 'module': module, 'request_id': request.get('request_id') if isinstance(request, dict) else None}
    if isinstance(request, dict) and isinstance(request.get('checks'), list):
        entry['checks'] = [{'id': c.get('id'), 'type': c.get('type'), 'target': c.get('target'),
                            'params_sha256': params_sha256(c.get('params'))} for c in request['checks'] if isinstance(c, dict)]
    if response:
        entry['results'] = [{'id': r['check_id'], 'result': r['result'], 'count': r['count']} for r in response['results']]
    if error:
        entry['error'] = error
    AUDIT.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(AUDIT, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'a') as handle:
        handle.write(json.dumps(entry, ensure_ascii=False) + '\n')


def handle(connection, module, uid, sources):
    """One newline-terminated JSON query per connection from the module's own uid."""
    import socket
    import struct
    peer_pid, peer_uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
    request, response = None, None
    try:
        if peer_uid != uid:
            raise XocError('peer_not_allowed', 'Only the module container user may query its evidence socket.')
        connection.settimeout(10)
        data = b''
        while not data.endswith(b'\n'):
            chunk = connection.recv(65536)
            if not chunk:
                break
            data += chunk
            if len(data) > MAX_REQUEST:
                raise XocError('request_too_large', 'Evidence query exceeds the size limit.')
        request = json.loads(data)
        response = evaluate(sources, request)
        connection.sendall(canonical(response) + b'\n')
        audit(module, request, response)
    except Exception as exc:  # noqa: BLE001 — every failure gets an answer and an audit line
        code = exc.code if isinstance(exc, XocError) else ('invalid_request' if isinstance(exc, ValueError) else 'internal_error')
        try:
            connection.sendall(canonical({'error': code}) + b'\n')
        except OSError:
            pass
        audit(module, request or {}, error=code)
    finally:
        connection.close()


def serve():
    """Serve every entitled module's socket until stopped (systemd: xocrange-evidence)."""
    import socket
    import threading
    _, engine, result = _installed()
    modules = evidence_modules(result)
    if not modules:
        return {'status': 'idle', 'modules': []}
    sources = host_sources(engine, result)
    project = result['compose']['name']
    listeners = []
    for module, (_, uid) in modules.items():
        directory = _volume(engine, project, f'evidence-{module}')
        path = directory / SOCKET_NAME
        if path.exists() or path.is_symlink():
            path.unlink()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(path))
        os.chown(path, uid, 0)
        os.chmod(path, 0o600)
        os.chown(directory, uid, 0)
        os.chmod(directory, 0o500)
        listener.listen(16)
        listeners.append((module, uid, listener))

    def accept(module, uid, listener):
        while True:
            connection, _ = listener.accept()
            threading.Thread(target=handle, args=(connection, module, uid, sources), daemon=True).start()

    threads = [threading.Thread(target=accept, args=item, daemon=True) for item in listeners]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return {'status': 'stopped', 'modules': sorted(modules)}


def install_credentials(identifier, source: Path):
    """Copy a module's Range Control URL, client certificate/key and CA into its credentials volume."""
    if os.geteuid() != 0:
        raise XocError('root_required', 'Module credentials require sudo.')
    _, engine, result = _installed()
    modules = evidence_modules(result)
    if identifier not in modules:
        raise XocError('module_not_entitled', 'The module is not installed with evidence-query.')
    target = _volume(engine, result['compose']['name'], f'module-{identifier}-credentials')
    uid = modules[identifier][1]
    for name in CREDENTIAL_FILES:
        data = read_bounded(Path(source), name)
        tmp = target / f'.{name}.tmp'
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
        os.chown(tmp, uid, 0)
        os.replace(tmp, target / name)
    os.chown(target, uid, 0)
    os.chmod(target, 0o500)
    return {'status': 'installed', 'module': identifier, 'files': list(CREDENTIAL_FILES)}


def reload_service():
    import subprocess
    if Path('/etc/systemd/system/xocrange-evidence.service').exists():
        subprocess.run(['systemctl', 'restart', 'xocrange-evidence'], capture_output=True, timeout=60)
