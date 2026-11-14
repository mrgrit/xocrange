"""Start the SIEM over for a new class: remove collected evidence and device logs.

An exercise analysed on top of earlier exercises mixes old alerts into new
findings. `xoc siem clear` removes, with the collector stopped:

- the local evidence store (raw records, C1 events, Wazuh alerts, outbox),
- the search indices built from it (`xoc-events-*`, `wazuh-alerts-4.x-*`),
- the Wazuh alert/archive logs and their dated generations,
- the firewall, IPS and WAF logs and their rotated generations.

Host logs (auditd, journald with Sysmon, osquery) belong to the operating
system and stay where they are; the collector resumes them from their current
end, so nothing before the clear is collected again. Accounts, device
policies, Core audit, learner records, enrolled agents, dashboards and the
retention policy are kept.
"""
import base64
import gzip
import os
from pathlib import Path
import re
import stat
import time

from .errors import XocError

# Installer state the collector and Indexer setup write once; not evidence.
PRESERVED_CURSORS = ('indexer-cluster', 'indexer-enabled', 'indexer-mapping',
                     'native-input-enabled', 'native-rules-revision')
DEVICE_LOGS = {'fw-logs': ('events.log',), 'ips-logs': ('eve.json',),
               'web-logs': ('access.log', 'error.log', 'modsec_audit.json', 'other_vhosts_access.log')}
MANAGER_LOGS = (('alerts', ('alerts.json', 'alerts.log'), 'ossec-alerts-'),
                ('archives', ('archives.json', 'archives.log'), 'ossec-archive-'))
INDICES = 'xoc-events-*,wazuh-alerts-4.x-*,wazuh-archives-4.x-*'
MONTHS = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec')


def _open_directory(base, *parts):
    """Open a directory below a validated volume without following any symlink.

    Containers can write their log volumes; a planted link must not redirect
    a root truncate or unlink to a host file.
    """
    fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    for part in parts:
        try:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        finally:
            os.close(fd)
        fd = child
    return fd


def _truncate(directory, name, report):
    try:
        fd = os.open(name, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except FileNotFoundError:
        return
    except OSError:
        report['skipped'].append(name)          # symlink, FIFO without reader, ...
        return
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            report['skipped'].append(name)
            return
        # Every writer appends (O_APPEND), so it continues at the new end.
        os.ftruncate(fd, 0)
        report['bytes'] += info.st_size
        report['truncated'] += 1
    finally:
        os.close(fd)


def _unlink(directory, name, report):
    info = os.stat(name, dir_fd=directory, follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode):
        report['skipped'].append(name)
        return
    os.unlink(name, dir_fd=directory)
    report['bytes'] += info.st_size
    report['removed'] += 1


def clear_device_logs(volumes):
    """Truncate current device logs and delete their rotated `.xoc-*` generations."""
    report = {'truncated': 0, 'removed': 0, 'bytes': 0, 'skipped': []}
    for volume, names in DEVICE_LOGS.items():
        if volume not in volumes:
            continue
        directory = _open_directory(volumes[volume])
        try:
            for name in names:
                _truncate(directory, name, report)
            for entry in os.listdir(directory):
                if any(re.fullmatch(re.escape(name) + r'\.xoc-\d{20}', entry) for name in names):
                    _unlink(directory, entry, report)
        finally:
            os.close(directory)
    return report


def clear_manager_logs(volumes):
    """Truncate Wazuh's alert/archive logs and delete its dated generations."""
    report = {'truncated': 0, 'removed': 0, 'bytes': 0, 'skipped': []}
    if 'siem-logs' not in volumes:
        return report
    base = volumes['siem-logs']
    for kind, names, stem in MANAGER_LOGS:
        try:
            directory = _open_directory(base, kind)
        except FileNotFoundError:
            continue
        except OSError:
            report['skipped'].append(kind)      # not a plain directory (e.g. a planted link)
            continue
        try:
            for name in names:
                _truncate(directory, name, report)
            years = [y for y in os.listdir(directory) if re.fullmatch(r'20\d\d', y)]
        finally:
            os.close(directory)
        for year in years:
            try:
                year_fd = _open_directory(base, kind, year)
            except OSError:
                report['skipped'].append(f'{kind}/{year}')
                continue
            try:
                months = [m for m in os.listdir(year_fd) if m in MONTHS]
            finally:
                os.close(year_fd)
            for month in months:
                try:
                    month_fd = _open_directory(base, kind, year, month)
                except OSError:
                    report['skipped'].append(f'{kind}/{year}/{month}')
                    continue
                try:
                    for entry in os.listdir(month_fd):
                        if entry.startswith(stem):
                            _unlink(month_fd, entry, report)
                finally:
                    os.close(month_fd)
    return report


def end_positions(path, owner, history=()):
    """Collector cursors that mark a host log and its generations as fully read.

    Mirrors `collector.read_snapshots`: same keys, anchors and file names, so
    the next poll continues after the current end instead of from the start.
    """
    states = {}
    for name in (*history, path + '.3', path + '.2', path + '.1', path):
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            continue
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            compressed = str(name).endswith('.gz')
            head = gzip.GzipFile(fileobj=stream).read(64) if compressed else stream.read(64)
            states[f'{owner}:{info.st_dev}:{info.st_ino}'] = {
                'offset': info.st_size, 'buffer': '', 'generation': 0,
                'anchor': base64.b64encode(head).decode(), 'file': str(name).removesuffix('.gz'),
                'complete': True, 'compressed_signature': [info.st_ino, info.st_size, info.st_mtime_ns] if compressed else None}
    return states


def reset_store(directory, host_files):
    """Replace the evidence database; keep installer cursors, skip existing host logs."""
    from .event_store import Store
    from .log_maintenance import history
    directory = Path(directory)
    old = Store(directory)
    try:
        kept = {name: old.cursor(name) for name in PRESERVED_CURSORS if old.cursor(name) is not None}
        from .retention import usage
        removed = usage(old)['used_bytes']
    finally:
        old.db.close()
    for suffix in ('', '-wal', '-shm'):
        path = directory / ('events.sqlite3' + suffix)
        if path.is_symlink():
            raise XocError('unsafe_store', 'Evidence database must not be a symlink.')
        path.unlink(missing_ok=True)
    store = Store(directory)
    try:
        with store.transaction():
            for name, value in kept.items():
                store.set_cursor(name, value)
            for source_id, path in host_files:
                for key, value in end_positions(path, source_id + ':host', history(path)).items():
                    store.set_cursor(key, value)
            store.set_cursor('sysmon-journal-resume', {'since': int(time.time())})
    finally:
        store.db.close()
    return removed


def delete_indices(client):
    status, rows = client.request('GET', '/_cat/indices/' + INDICES + '?format=json&h=index&expand_wildcards=all')
    if status != 200 or not isinstance(rows, list):
        raise XocError('clear_indices', 'Cannot list the SIEM search indices.')
    deleted = 0
    for row in rows:
        name = row.get('index', '') if isinstance(row, dict) else ''
        if not re.fullmatch(r'(xoc-events-|wazuh-alerts-4\.x-|wazuh-archives-4\.x-)[0-9.-]+', name):
            continue
        code, _ = client.request('DELETE', '/' + name)
        if code not in (200, 404):
            raise XocError('clear_indices', 'The Indexer refused to delete a SIEM index.')
        deleted += 1
    return deleted


def clear(store_directory=Path('/var/lib/xocrange/siem'), *, confirmed=False):
    from . import operations as ops
    from .collector import FILES
    from .lab import Docker
    from .retention import usage
    state = ops.installed()
    selected = set(state['selected'])
    if 'siem' not in selected:
        raise XocError('siem_not_selected', 'The SIEM is not installed.')
    volumes = ops.volume_paths()
    if not confirmed:
        from .event_store import Store
        store = Store(store_directory)
        try:
            evidence = usage(store)['used_bytes']
        finally:
            store.db.close()
        logs = sum((volumes[v] / n).stat().st_size for v, names in DEVICE_LOGS.items() if v in volumes
                   for n in names if (volumes[v] / n).is_file() and not (volumes[v] / n).is_symlink())
        return {'status': 'confirmation-required', 'evidence_bytes': evidence, 'device_log_bytes': logs,
                'search_indices': 'siem-ui' in selected, 'confirm': 'sudo xoc siem clear --yes',
                'kept': ['accounts', 'device policies', 'Core audit', 'learner records', 'enrolled agents',
                         'dashboards', 'retention policy', 'host logs (collection resumes from now)']}
    collector = 'xocrange-collector.service'
    running = ops.command(['systemctl', 'is-active', '--quiet', collector], check=False).returncode == 0
    ops.command(['systemctl', 'stop', collector], timeout=300)
    try:
        indices = 0
        if 'siem-ui' in selected:
            from .indexer import Client
            directory = Path(state['release']) / '.local/plans' / state['plan']
            indices = delete_indices(Client(Docker(directory / 'compose.yaml', ops.PROJECT), ops.PROJECT, user='admin'))
        manager = clear_manager_logs(volumes)
        devices = clear_device_logs(volumes)
        host_files = [(source_id, path) for _, source_id, service, _, path in FILES if service is None]
        evidence = reset_store(store_directory, host_files)
    finally:
        if running:
            ops.command(['systemctl', 'start', collector], timeout=300)
    return {'status': 'cleared', 'evidence_bytes_removed': evidence, 'search_indices_deleted': indices,
            'manager_logs': manager, 'device_logs': devices,
            'host_logs': 'kept; collection resumes from their current end',
            'collector': 'restarted' if running else 'was not running'}
