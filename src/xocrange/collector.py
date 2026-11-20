"""Local source registry, restart-safe cursors and Wazuh analysis acknowledgments."""
import base64
from datetime import datetime, timezone, timedelta
import fcntl
import hashlib
import gzip
import json
import os
from pathlib import Path
import selectors
import subprocess
import time

from .documents import MAX_BYTES, canonical
from .endpoint_events import AUDIT_HEADER
from .errors import XocError
from .event_store import Store, now
from .lab import Docker, checked_plan

# Seconds of retention work per collector loop (see Store.prune); while a
# pass is unfinished it replaces the loop's 5 s idle wait.
MAINTENANCE_BUDGET = 4

# Paths and identities are installer-owned, never taken from incoming records.
FILES = (
    ("nftables", "fw-nftables", "fw", "0:0", "/var/log/nftables/events.log"),
    ("suricata", "ips-suricata", "ips", "0:0", "/var/log/suricata/eve.json"),
    ("modsecurity", "web-modsecurity", "web", "33:33", "/var/log/apache2/modsec_audit.json"),
    ("apache-access", "web-access", "web", "33:33", "/var/log/apache2/access.log"),
    ("apache-error", "web-error", "web", "33:33", "/var/log/apache2/error.log"),
    ("osquery", "host-osquery-results", None, None, "/var/log/xocrange/osquery/osqueryd.results.log"),
    ("osquery", "host-osquery-snapshots", None, None, "/var/log/xocrange/osquery/osqueryd.snapshots.log"),
    ("auditd", "host-auditd", None, None, "/var/log/audit/audit.log"),
)

# Used on the host and via docker exec; only immutable registry paths are passed.
# Read each inode once across rename rotation. Offset resets detect copy-truncate.
def read_snapshots(path, owner, states, limit=262144, history=(), rotations=True):
    result = []
    seen = set()
    remaining = limit
    names = (*history, path + '.3', path + '.2', path + '.1', path) if rotations else (path,)
    for name in names:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            continue
        with os.fdopen(fd, 'rb') as raw_stream:
            stat = os.fstat(raw_stream.fileno())
            compressed = str(name).endswith('.gz')
            stream = gzip.GzipFile(fileobj=raw_stream) if compressed else raw_stream
            key = f'{owner}:{stat.st_dev}:{stat.st_ino}'
            logical = str(name).removesuffix('.gz')
            if compressed:
                key = next((k for k,v in states.items() if v.get('file')==logical), key)
            if key in seen:
                continue
            seen.add(key)
            prior = states.get(key, {})
            signature = [stat.st_ino, stat.st_size, stat.st_mtime_ns] if compressed else None
            if compressed and prior.get('complete') and prior.get('compressed_signature') == signature:
                stream.close()
                continue
            head = stream.read(64)
            old = base64.b64decode(prior.get('anchor', ''))
            reset = (not compressed and stat.st_size < prior.get('offset', 0)) or not head.startswith(old)
            offset = 0 if reset else prior.get('offset', 0)
            stream.seek(offset)
            requested = max(0, remaining)
            data = stream.read(requested)
            remaining -= len(data)
            result.append(dict(key=key, reset=reset, offset=offset,
                               anchor=base64.b64encode(head).decode(), data=base64.b64encode(data).decode(),
                               file=logical, complete=len(data)<requested, compressed_signature=signature))
            if compressed: stream.close()
            if remaining <= 0:
                break
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


class Transport:
    """One long-lived local transport process per Wazuh queue.

    Spawning `compose exec` for every batch made the collector's own docker,
    compose, runc and Python processes into Sysmon observations, which the next
    spawn then delivered: a self-sustaining loop of evidence about delivery.
    The queue scripts already stream one acknowledgment per input line.
    """
    def __init__(self, command):
        self.command = list(command)
        self.process = None

    def close(self, kill=False):
        process, self.process = self.process, None
        if process is None:
            return
        if kill:
            process.kill()
        else:
            try:
                process.stdin.close()
            except OSError:
                pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    def send(self, payload, ids, timeout=30):
        """Write newline frames and return the acknowledged ids, in order.

        On failure the process is discarded and ``exc.acked`` holds the ids
        acknowledged before the failure, so they are not redelivered.
        """
        acked = []
        if not ids:
            return acked
        pending, buffer = memoryview(payload), b''
        deadline = time.monotonic() + timeout
        code, message = 'collection_command', 'A local collection/analysis command failed.'
        try:
            if self.process is None or self.process.poll() is not None:
                self.close()
                self.process = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                                stderr=subprocess.DEVNULL)
                os.set_blocking(self.process.stdin.fileno(), False)
                os.set_blocking(self.process.stdout.fileno(), False)
            writer, reader = self.process.stdin.fileno(), self.process.stdout.fileno()
            with selectors.DefaultSelector() as selector:
                if pending:
                    selector.register(writer, selectors.EVENT_WRITE)
                selector.register(reader, selectors.EVENT_READ)
                while len(acked) < len(ids):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError
                    for key, _ in selector.select(remaining):
                        if key.fd == writer:
                            pending = pending[os.write(writer, pending[:65536]):]
                            if not pending:
                                selector.unregister(writer)
                            continue
                        data = os.read(reader, 65536)
                        if not data:
                            raise EOFError
                        *lines, buffer = (buffer + data).split(b'\n')
                        for line in lines:
                            if len(acked) == len(ids) or line.decode(errors='replace') != ids[len(acked)]:
                                code, message = 'transport_ack', 'Transport acknowledgment differs from the outbox.'
                                raise ValueError
                            acked.append(ids[len(acked)])
                if buffer:
                    code, message = 'transport_ack', 'Transport acknowledgment differs from the outbox.'
                    raise ValueError
        except (OSError, EOFError, TimeoutError, ValueError) as exc:
            self.close(kill=True)
            error = XocError(code, message)
            error.acked = acked
            raise error from exc
        return acked


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
        # C1 v0.3: activity logs of entitled agent modules (tool receipts), one source per module.
        self.activity = {}
        for name in sorted((result['compose'].get('volumes') or {})):
            if not name.startswith('activity-'):
                continue
            volume, = json.loads(self.engine.run(['volume', 'inspect', result['compose']['name'] + '_' + name]))
            labels = volume.get('Labels') or {}
            mount = Path(volume['Mountpoint'])
            if (labels.get('com.docker.compose.project') != result['compose']['name'] or labels.get('com.docker.compose.volume') != name
                    or volume.get('Driver') != 'local' or not mount.is_absolute() or any(p.is_symlink() for p in (mount, *mount.parents))):
                raise XocError('untrusted_log_volume', 'Activity volume ownership differs from the validated plan.')
            self.activity['agent-' + name.removeprefix('activity-')] = mount / 'activity.jsonl'
        # C1 v0.4: what happened in the facility simulator (ADR 0014). The module writes
        # events.jsonl on its state volume; one module at most holds that volume.
        self.facility = None
        if 'facility-state' in (result['compose'].get('volumes') or {}):
            volume, = json.loads(self.engine.run(['volume', 'inspect', result['compose']['name'] + '_facility-state']))
            labels = volume.get('Labels') or {}
            mount = Path(volume['Mountpoint'])
            if (labels.get('com.docker.compose.project') != result['compose']['name'] or labels.get('com.docker.compose.volume') != 'facility-state'
                    or volume.get('Driver') != 'local' or not mount.is_absolute() or any(p.is_symlink() for p in (mount, *mount.parents))):
                raise XocError('untrusted_log_volume', 'Facility volume ownership differs from the validated plan.')
            self.facility = mount / 'events.jsonl'
        from .entitlements import collection_identity
        self.store = Store(directory, identity=collection_identity(root))
        self.indexer = None
        if 'siem-ui' in result['lock']['selected']:
            from .indexer import Client
            self.indexer = Client(self.engine,result['compose']['name'])
        with self.store.transaction():
            self.store.set_cursor('indexer-enabled', bool(self.indexer))
            self.store.set_cursor('native-input-enabled', True)
            revision=hashlib.sha256(b''.join((root/'components/siem'/name).read_bytes() for name in ('Dockerfile','native-decoders.xml','native-rules.xml'))).hexdigest()
            if self.store.cursor('native-rules-revision') != revision:
                self.store.db.execute("UPDATE native_inputs SET error=NULL,sent=NULL WHERE error='native_decoder_missing'")
                self.store.set_cursor('native-rules-revision',revision)
            if not self.indexer:
                self.store.db.execute("DELETE FROM health WHERE source IN ('indexer','native-indexer')")
        self.lock = open(self.store.directory / 'collector.lock', 'a')
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise XocError('collector_running', 'Only one collector may own this evidence store.') from exc

    def deliver(self, script, table, payload, ids, ack_code):
        transports = self.__dict__.setdefault('transports', {})
        if script not in transports:
            transports[script] = Transport(self.engine.compose + ['exec', '-T', '--user', '999:999', 'siem',
                                           '/var/ossec/framework/python/bin/python3', '-B', '/usr/local/lib/' + script])
        error = None
        try:
            acked = transports[script].send(payload, ids)
        except XocError as exc:
            acked = exc.acked
            error = XocError(ack_code, 'Wazuh transport acknowledgment differs from the outbox.') if exc.code == 'transport_ack' else exc
        if acked:
            with self.store.db:
                self.store.db.executemany(f'UPDATE {table} SET sent=? WHERE id=?', [(now(), value) for value in acked])
        if error:
            raise error

    def close(self):
        for transport in self.__dict__.get('transports', {}).values():
            transport.close()

    def read_files(self, source_id, service, user, path):
        if service:
            name, mount, base = self.volumes[service]
            relative = Path(path).relative_to(base)
            path = str(mount / relative)
            owner = source_id + ':' + name
        else:
            owner = source_id + ':host'
        states = {row[0]: json.loads(row[1]) for row in self.store.db.execute('SELECT name,value FROM cursors WHERE name LIKE ?', (owner + ':%',))}
        from .retention import retained_manager_paths
        from .log_maintenance import history as source_history
        history = retained_manager_paths(path) if service == 'siem' else source_history(path)
        if service == 'siem':
            live = read_snapshots(path, owner, states, 8*MAX_BYTES)
            live_keys = {chunk['key'] for chunk in live}
            history = [p for p in history if f'{owner}:{p.stat().st_dev}:{p.stat().st_ino}' not in live_keys]
            # Preserve low latency for current input while draining rotated files.
            older = read_snapshots(path, owner, states, 24*MAX_BYTES, history)
            return live + [chunk for chunk in older if chunk['key'] not in live_keys]
        # Current files receive their own read budget while rotated generations
        # drain. One large, unread old file cannot monopolize every source poll.
        live = read_snapshots(path, owner, states, 2*MAX_BYTES, rotations=False)
        live_keys = {chunk['key'] for chunk in live}
        older = read_snapshots(path, owner, states, 2*MAX_BYTES, history)
        return live + [chunk for chunk in older if chunk['key'] not in live_keys]

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

    def unterminated(self, source, source_id, position, raw, truncated=False):
        """Handle a tail without a newline: the file shrank, or the line is over budget."""
        if source not in ('wazuh', 'wazuh-archive'):
            self.store.ingest(source, source_id, position, raw)
        elif truncated:
            # Manager output is a receipt stream with no C1 adapter (see Store.drop_fragment).
            self.store.drop_fragment(source)
        else:
            self.store.processing_error(source, raw, 'analysis_oversize')

    def accept_chunk(self, source, source_id, chunk):
        store = self.store
        key = chunk['key']
        previous = store.cursor(key) or {'offset': 0, 'buffer': '', 'generation': 0}
        if chunk['reset']:
            if previous['buffer']:
                self.unterminated(source, source_id, f"{key}:{previous['generation']}:truncated", base64.b64decode(previous['buffer']), truncated=True)
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
            elif source in ('wazuh', 'wazuh-archive'):
                if not store.db.in_transaction: store.db.execute('BEGIN')
                store.db.execute('SAVEPOINT analysis_record')
                try:
                    value = json.loads(raw)
                    if not isinstance(value,dict): raise ValueError()
                    if source == 'wazuh':
                        self.store.confirm(value)
                        from .native_alerts import accept
                        accept(self.store,raw)
                    else:
                        from .native_input import confirm
                        confirm(self.store,value)
                except (ValueError, TypeError, AttributeError, XocError) as exc:
                    store.db.execute('ROLLBACK TO analysis_record')
                    if getattr(exc,'code','') in ('store_full','disk_reserve'): raise
                    self.store.processing_error(source,raw,getattr(exc,'code','invalid_analysis_json'))
                finally:
                    store.db.execute('RELEASE analysis_record')
            elif raw.strip():
                store.ingest(source, source_id, position, raw)
            consumed = end
        remaining = buffer[consumed:]
        if len(remaining) > MAX_BYTES:
            self.unterminated(source, source_id, f"{key}:{previous['generation']}:{base+consumed}", remaining)
            remaining = b''
        store.set_cursor(key, {'offset': chunk['offset'] + len(data), 'buffer': base64.b64encode(remaining).decode(),
                               'generation': previous['generation'], 'anchor': chunk['anchor'],
                               'file': chunk.get('file'), 'complete': chunk.get('complete',False),
                               'compressed_signature':chunk.get('compressed_signature')})

    def sysmon(self):
        state = self.store.cursor('sysmon-journal')
        # Without --all, journald replaces fields over 4096 bytes with null.
        args = ['journalctl', '-t', 'sysmon', '--output=json', '--all', '--no-pager']
        resume = self.store.cursor('sysmon-journal-resume')
        args += ['--after-cursor', state['cursor']] if state else ['--since', '@'+str(resume['since']) if resume else '-1 hour']
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        limited = False
        deadline = time.monotonic() + 5
        latest = state.get('source_time') if state else None
        try:
            with self.store.transaction():
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
                    self.store.ingest('sysmon', 'host-sysmon', cursor, raw_message)
                    latest = int(record['__REALTIME_TIMESTAMP']) / 1000000
                    self.store.set_cursor('sysmon-journal', {'cursor': cursor, 'source_time': latest})
                    if resume:
                        self.store.db.execute('DELETE FROM cursors WHERE name=?', ('sysmon-journal-resume',))
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
            self.deliver('xoc-queue.py', 'events', b''.join(row['event'].encode() + b'\n' for row in pending),
                         [r['id'] for r in pending], 'siem_transport')
        # A successful send is NOT a decode acknowledgment. Read actual analysisd alerts.
        self.store.health('wazuh', 'ready')

    def forward_native(self):
        from .native_input import pending
        # Archives acknowledge processing, including legitimate level-zero and
        # no_log rules. A socket send alone never marks an input as decoded.
        chunks = self.read_files('wazuh-archives', 'siem', '999:999', '/var/ossec/logs/archives/archives.json')
        with self.store.transaction():
            for chunk in chunks:
                self.accept_chunk('wazuh-archive', 'wazuh-archives', chunk)
        values = pending(self.store)
        if values:
            self.deliver('xoc-native-queue.py', 'native_inputs', b''.join(canonical(value)+b'\n' for value in values),
                         [row['id'] for row in values], 'native_transport')
        return 'ready'

    def once(self):
        if time.monotonic() - getattr(self, '_last_health', -60) >= 30:
            self._last_health = time.monotonic()
            units = ['sysmon.service', 'auditd.service', 'xocrange-osquery.service']
            probe = subprocess.run(['systemctl', 'is-active', *units], capture_output=True, text=True, timeout=10)
            statuses = probe.stdout.splitlines()
            for index, unit in enumerate(units):
                self.store.health('sensor-' + unit.removesuffix('.service'), 'ready' if index < len(statuses) and statuses[index] == 'active' else 'inactive')
            # An active auditd can still have stopped writing (full partition);
            # log maintenance refreshes this report every minute and resumes it.
            from .log_maintenance import audit_state
            report = audit_state()
            if report and 'logging suspended = yes' in report:
                self.store.health('sensor-auditd', 'logging_suspended')
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
        sources = [('xoc-agent', source_id, path) for source_id, path in getattr(self, 'activity', {}).items()]
        if getattr(self, 'facility', None):
            sources.append(('xoc-facility', 'facility-events', self.facility))
        for source, source_id, path in sources:
            try:
                chunks = self.read_files(source_id, None, None, str(path))
                with self.store.transaction():
                    for chunk in chunks:
                        self.accept_chunk(source, source_id, chunk)
                self.store.health(source_id, 'ready' if chunks else 'awaiting-file')
            except (XocError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
                self.store.health(source_id, getattr(exc, 'code', 'collection_failed'))
        try:
            with self.store.transaction():
                for key, value in self.store.db.execute("SELECT name,value FROM cursors WHERE name LIKE 'audit:%'").fetchall():
                    group = json.loads(value)
                    if time.time() - group['touched'] >= 2:
                        self.store.ingest('auditd', group['source_id'], group['position'], base64.b64decode(group['raw']))
                        self.store.db.execute('DELETE FROM cursors WHERE name=?', (key,))
        except XocError as exc:
            self.store.health('host-auditd', exc.code)
        for name, method in [('host-sysmon', self.sysmon), ('wazuh', self.forward), ('wazuh-native', self.forward_native)]:
            try:
                status = method()
                self.store.health(name, status or 'ready')
            except (XocError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
                self.store.health(name, getattr(exc, 'code', 'collection_failed'))
        if self.indexer:
            from .indexer import export
            try:
                for _ in range(4):
                    state = export(self.store,self.indexer)
                    if state != 'ready' or not self.store.db.execute('SELECT 1 FROM events WHERE confirmed IS NOT NULL AND indexed IS NULL LIMIT 1').fetchone(): break
                self.store.health('indexer', state)
            except (XocError,OSError,ValueError) as exc:
                self.store.health('indexer',getattr(exc,'code','indexer_failed'))
            from .native_alerts import export as export_native
            try:
                for _ in range(8):
                    state = export_native(self.store,self.indexer)
                    if state != 'ready' or not self.store.db.execute('SELECT 1 FROM wazuh_alerts WHERE indexed IS NULL LIMIT 1').fetchone(): break
                self.store.health('native-indexer', state)
            except (XocError,OSError,ValueError) as exc:
                self.store.health('native-indexer',getattr(exc,'code','native_indexer_failed'))
        return self.store.status()

    def maintain(self, budget=MAINTENANCE_BUDGET):
        """One bounded slice of retention work; True when the pass is complete.

        Collection, delivery and export must keep running while expired rows
        are removed, so a long pass is spread over several loops. A slice that
        removed rows refreshes the retention health: on the demo Core one pass
        over a busy day's expiry took 73 minutes and the SIEM showed degraded
        all that time although deletion was working. A slice that removes
        nothing does not, so a stuck pass still goes stale; disk use has its
        own limit in Store.status.
        """
        import sqlite3
        from .retention import maintain
        try:
            if not self.store.prune(budget=budget):
                if getattr(self.store, 'prune_deleted', 0):
                    self.store.health('retention', 'ready')
                return False
            self.store.health('retention', maintain(self))
        except (XocError, OSError, ValueError, sqlite3.DatabaseError):
            self.store.health('retention', 'maintenance_failed')
        return True

    def run(self):
        last_maintenance, maintaining = -300, False
        while True:
            self.once()
            if maintaining or time.monotonic()-last_maintenance >= 300:
                maintaining = not self.maintain()
                if maintaining:
                    # An unfinished pass uses the idle wait: the loop period
                    # stays the same and deletion keeps up with ingestion.
                    continue
                last_maintenance = time.monotonic()
            time.sleep(5)
