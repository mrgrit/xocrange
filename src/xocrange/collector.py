"""Local source registry, restart-safe cursors and Wazuh analysis acknowledgments."""
import base64
from datetime import datetime, timezone, timedelta
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

from .documents import MAX_BYTES, canonical
from .endpoint_events import AUDIT_HEADER
from .errors import XocError
from .event_store import Store, now
from .lab import Docker, checked_plan

# Paths and identities are installer-owned, never taken from incoming records.
FILES = (
    ("nftables", "fw-nftables", "fw", "0:0", "/var/log/nftables/events.log"),
    ("suricata", "ips-suricata", "ips", "0:0", "/var/log/suricata/eve.json"),
    ("modsecurity", "web-modsecurity", "web", "33:33", "/var/log/apache2/modsec_audit.json"),
    ("apache-access", "web-access", "web", "33:33", "/var/log/apache2/access.json"),
    ("apache-error", "web-error", "web", "33:33", "/var/log/apache2/error.log"),
    ("osquery", "host-osquery-results", None, None, "/var/log/xocrange/osquery/osqueryd.results.log"),
    ("osquery", "host-osquery-snapshots", None, None, "/var/log/xocrange/osquery/osqueryd.snapshots.log"),
    ("auditd", "host-auditd", None, None, "/var/log/audit/audit.log"),
)

# Used on the host and via docker exec; only immutable registry paths are passed.
# Read each inode once across rename rotation. Offset resets detect copy-truncate.
def read_snapshots(path, owner, states, limit=262144):
    result = []
    for name in (path + '.2', path + '.1', path):
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            continue
        with os.fdopen(fd, 'rb') as stream:
            stat = os.fstat(stream.fileno())
            key = f'{owner}:{stat.st_dev}:{stat.st_ino}'
            prior = states.get(key, {})
            head = stream.read(64)
            old = base64.b64decode(prior.get('anchor', ''))
            reset = stat.st_size < prior.get('offset', 0) or not head.startswith(old)
            offset = 0 if reset else prior.get('offset', 0)
            stream.seek(offset)
            data = stream.read(limit)
            result.append(dict(key=key, reset=reset, offset=offset,
                               anchor=base64.b64encode(head).decode(), data=base64.b64encode(data).decode()))
    return result



def framed(buffer, multiline=False):
    """Return complete byte frames plus their offsets; leave partial writes pending."""
    offset = 0
    while offset < len(buffer):
        start = offset
        if multiline:
            while offset < len(buffer) and buffer[offset:offset+1].isspace():
                offset += 1
            start = offset
            if start == len(buffer):
                break
            if buffer[start:start+1] == b'{':
                depth, quoted, escaped, end = 0, False, False, None
                for index in range(start, len(buffer)):
                    ch = buffer[index]
                    if quoted:
                        if escaped:
                            escaped = False
                        elif ch == 92:
                            escaped = True
                        elif ch == 34:
                            quoted = False
                    elif ch == 34:
                        quoted = True
                    elif ch in (123, 91):
                        depth += 1
                    elif ch in (125, 93):
                        depth -= 1
                        if depth == 0:
                            end = index + 1
                            break
                if end is None:
                    break
            else:
                end = buffer.find(b'\n', start)
                if end < 0:
                    break
                end += 1
        else:
            end = buffer.find(b'\n', start)
            if end < 0:
                break
            end += 1
        yield start, end, buffer[start:end]
        offset = end


class Collector:
    def __init__(self, root, plan_name, directory):
        plan_dir, result = checked_plan(root, plan_name)
        if 'siem' not in result['lock']['selected']:
            raise XocError('siem_not_selected', 'Select the SIEM component before starting its collector.')
        self.engine = Docker(plan_dir / 'compose.yaml', result['compose']['name'])
        endpoint = self.engine.run(['context', 'inspect', 'default', '--format', '{{.Endpoints.docker.Host}}']).strip()
        if endpoint not in ('unix:///var/run/docker.sock', 'unix:///run/docker.sock'):
            raise XocError('local_daemon_required', 'The local collector requires the local Docker daemon.')
        self.volumes = {}
        for service, short, base in [('fw','fw-logs','/var/log/nftables'), ('ips','ips-logs','/var/log/suricata'),
                                     ('web','web-logs','/var/log/apache2'), ('siem','siem-logs','/var/ossec/logs')]:
            name = result['compose']['name'] + '_' + short
            volume, = json.loads(self.engine.run(['volume', 'inspect', name]))
            labels = volume.get('Labels') or {}
            if labels.get('com.docker.compose.project') != result['compose']['name'] or labels.get('com.docker.compose.volume') != short or volume.get('Driver') != 'local':
                raise XocError('untrusted_log_volume', 'Log volume ownership differs from the validated plan.')
            mount = Path(volume['Mountpoint'])
            if not mount.is_absolute() or any(p.is_symlink() for p in (mount, *mount.parents)):
                raise XocError('untrusted_log_volume', 'Log volume path is not a local, direct directory.')
            self.volumes[service] = (name, mount, base)
        self.store = Store(directory)
        self.indexer = None
        if 'siem-ui' in result['lock']['selected']:
            from .indexer import Client
            self.indexer = Client(self.engine,result['compose']['name'])
        with self.store.transaction():
            self.store.set_cursor('indexer-enabled', bool(self.indexer))
            if not self.indexer:
                self.store.db.execute("DELETE FROM health WHERE source='indexer'")
        self.lock = open(self.store.directory / 'collector.lock', 'a')
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise XocError('collector_running', 'Only one collector may own this evidence store.') from exc

    def execute(self, args, payload, timeout=30):
        result = subprocess.run(args, input=payload, capture_output=True, timeout=timeout)
        if result.returncode:
            raise XocError('collection_command', 'A local collection/analysis command failed.')
        return result.stdout

    def read_files(self, source_id, service, user, path):
        if service:
            name, mount, base = self.volumes[service]
            relative = Path(path).relative_to(base)
            path = str(mount / relative)
            owner = source_id + ':' + name
        else:
            owner = source_id + ':host'
        states = {row[0]: json.loads(row[1]) for row in self.store.db.execute('SELECT name,value FROM cursors WHERE name LIKE ?', (owner + ':%',))}
        return read_snapshots(path, owner, states, 32 * MAX_BYTES if service == 'siem' else 262144)

    def accept_audit_line(self, source_id, position, raw):
        try:
            match = AUDIT_HEADER.fullmatch(raw.decode().strip())
        except UnicodeError:
            match = None
        if not match:
            self.store.ingest('auditd', source_id, position, raw)
            return
        node, kind, stamp, serial, tail = match.groups()
        key = 'audit:' + hashlib.sha256(canonical([source_id, node, stamp, serial])).hexdigest()
        group = self.store.cursor(key) or {'raw': '', 'position': position, 'source_id': source_id}
        combined = base64.b64decode(group['raw']) + raw
        group.update(raw=base64.b64encode(combined).decode(), touched=time.time())
        if kind == 'EOE' or len(combined) > MAX_BYTES:
            self.store.ingest('auditd', source_id, group['position'], combined)
            self.store.db.execute('DELETE FROM cursors WHERE name=?', (key,))
        else:
            self.store.set_cursor(key, group)

    def accept_chunk(self, source, source_id, chunk):
        store = self.store
        key = chunk['key']
        previous = store.cursor(key) or {'offset': 0, 'buffer': '', 'generation': 0}
        if chunk['reset']:
            if previous['buffer']:
                store.ingest(source, source_id, f"{key}:{previous['generation']}:truncated", base64.b64decode(previous['buffer']))
            previous = {'offset': 0, 'buffer': '', 'generation': previous['generation'] + 1}
        retained = base64.b64decode(previous['buffer'])
        base = chunk['offset'] - len(retained)
        data = base64.b64decode(chunk['data'])
        buffer = retained + data
        consumed = 0
        for start, end, raw in framed(buffer, source == 'modsecurity'):
            position = f"{key}:{previous['generation']}:{base+start}"
            if source == 'auditd':
                self.accept_audit_line(source_id, position, raw)
            elif source == 'wazuh':
                self.store.confirm(json.loads(raw))
            elif raw.strip():
                store.ingest(source, source_id, position, raw)
            consumed = end
        remaining = buffer[consumed:]
        if len(remaining) > MAX_BYTES:
            store.ingest(source, source_id, f"{key}:{previous['generation']}:{base+consumed}", remaining)
            remaining = b''
        store.set_cursor(key, {'offset': chunk['offset'] + len(data), 'buffer': base64.b64encode(remaining).decode(),
                               'generation': previous['generation'], 'anchor': chunk['anchor']})

    def sysmon(self):
        state = self.store.cursor('sysmon-journal')
        # Without --all, journald replaces fields over 4096 bytes with null.
        args = ['journalctl', '-t', 'sysmon', '--output=json', '--all', '--no-pager']
        args += ['--after-cursor', state['cursor']] if state else ['--since', '-1 hour']
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        limited = False
        deadline = time.monotonic() + 5
        latest = state.get('source_time') if state else None
        try:
            for count in range(4096):
                if count and time.monotonic() >= deadline:
                    limited = True
                    break
                line = process.stdout.readline(MAX_BYTES + 1)
                if not line:
                    break
                if len(line) > MAX_BYTES:
                    raise XocError('journal_oversize', 'Sysmon journal record exceeds its budget.')
                record = json.loads(line)
                message, cursor = record.get('MESSAGE'), record.get('__CURSOR')
                if not isinstance(cursor, str):
                    raise XocError('journal_format', 'Sysmon journal record has no usable cursor.')
                if isinstance(message,str):
                    raw_message=message.encode()
                elif isinstance(message,list) and all(type(n) is int and 0 <= n <= 255 for n in message):
                    raw_message=bytes(message)
                else:
                    # Preserve an invalid record for quarantine and advance past
                    # it; one malformed MESSAGE must not stall the journal.
                    raw_message=json.dumps(record).encode()
                with self.store.transaction():
                    self.store.ingest('sysmon', 'host-sysmon', cursor, raw_message)
                    latest = int(record['__REALTIME_TIMESTAMP']) / 1000000
                    self.store.set_cursor('sysmon-journal', {'cursor': cursor, 'source_time': latest})
            else:
                limited = True
            if not limited and process.wait(timeout=5) != 0:
                raise XocError('journal_cursor', 'Journal cursor is unavailable; inspect journal retention before recovery.')
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)
        return 'lagging' if latest and time.time() - latest > 120 else 'ready'

    def forward(self):
        # Drain analysis acknowledgments before deciding which frames need retry.
        # Alerts contain both decoded fields and full_log and are larger than C1.
        chunks = self.read_files('wazuh-alerts', 'siem', '999:999', '/var/ossec/logs/alerts/alerts.json')
        with self.store.transaction():
            for chunk in chunks:
                self.accept_chunk('wazuh', 'wazuh-alerts', chunk)
        pending = self.store.pending()
        if pending:
            command = self.engine.compose + ['exec', '-T', '--user', '999:999', 'siem',
                        '/var/ossec/framework/python/bin/python3', '-B', '/usr/local/lib/xoc-queue.py']
            ack = self.execute(command, b''.join(row['event'].encode() + b'\n' for row in pending)).decode().splitlines()
            if ack != [r['id'] for r in pending]:
                raise XocError('siem_transport', 'Wazuh transport acknowledgment differs from the outbox.')
            with self.store.db:
                self.store.db.executemany('UPDATE events SET sent=? WHERE id=?', [(now(), value) for value in ack])
        # A successful send is NOT a decode acknowledgment. Read actual analysisd alerts.
        self.store.health('wazuh', 'ready')

    def once(self):
        if time.monotonic() - getattr(self, '_last_health', -60) >= 30:
            self._last_health = time.monotonic()
            units = ['sysmon.service', 'auditd.service', 'xocrange-osquery.service']
            probe = subprocess.run(['systemctl', 'is-active', *units], capture_output=True, text=True, timeout=10)
            statuses = probe.stdout.splitlines()
            for index, unit in enumerate(units):
                self.store.health('sensor-' + unit.removesuffix('.service'), 'ready' if index < len(statuses) and statuses[index] == 'active' else 'inactive')
            try:
                running = self.engine.run(['ps', '--status', 'running', '--services'], compose=True).splitlines()
                self.store.health('wazuh-process', 'ready' if 'siem' in running else 'inactive')
            except XocError:
                self.store.health('wazuh-process', 'unavailable')
        for source, source_id, service, user, path in FILES:
            try:
                chunks = self.read_files(source_id, service, user, path)
                with self.store.transaction():
                    for chunk in chunks:
                        self.accept_chunk(source, source_id, chunk)
                self.store.health(source_id, 'ready' if chunks else 'awaiting-file')
            except (XocError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
                self.store.health(source_id, getattr(exc, 'code', 'collection_failed'))
        with self.store.transaction():
            for key, value in self.store.db.execute("SELECT name,value FROM cursors WHERE name LIKE 'audit:%'").fetchall():
                group = json.loads(value)
                if time.time() - group['touched'] >= 2:
                    self.store.ingest('auditd', group['source_id'], group['position'], base64.b64decode(group['raw']))
                    self.store.db.execute('DELETE FROM cursors WHERE name=?', (key,))
        for name, method in [('host-sysmon', self.sysmon), ('wazuh', self.forward)]:
            try:
                status = method()
                self.store.health(name, status or 'ready')
            except (XocError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
                self.store.health(name, getattr(exc, 'code', 'collection_failed'))
        if self.indexer:
            from .indexer import export
            try:
                self.store.health('indexer',export(self.store,self.indexer))
            except (XocError,OSError,ValueError) as exc:
                self.store.health('indexer',getattr(exc,'code','indexer_failed'))
        return self.store.status()

    def run(self):
        iteration = 0
        while True:
            self.once()
            if iteration % 120 == 0:
                self.store.prune()
            iteration += 1
            time.sleep(5)
