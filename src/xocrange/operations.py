"""Privileged, serialized backups and rollback for the installer-owned appliance.

Backups are private directories, with independently hashed archives. Extraction
never follows archive links; only reviewed xOC paths and labelled volumes change.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sqlite3
import stat
import subprocess
import tarfile
import time
import tempfile

from .errors import XocError
from .entitlements import atomic

STATE = Path('/var/lib/xocrange')
PREFIX = Path('/opt/xocrange')
PROJECT = 'xoc-core-security-path'
UNITS = ('xocrange-log-maintenance.timer', 'xocrange-log-maintenance.service',
         'xocrange-observer.timer', 'xocrange-observer.service', 'xocrange-collector.service',
         'xocrange-evidence.service', 'xocrange-osquery.service', 'sysmon.service', 'xocrange-core.service')
OWNED_UNITS = tuple(u for u in UNITS if u != 'sysmon.service')
STATE_NAMES = ('platform', 'ui', 'manager', 'siem', 'osquery', 'last-install.json',
               'installer-owned', 'storage-configured', 'telemetry-owned', 'release-inventory.json')
HOST_PATHS = {'etc': Path('/etc/xocrange'), 'wrapper': Path('/usr/local/bin/xoc'),
              'audit-rule': Path('/etc/audit/rules.d/70-xocrange.rules'),
              'logrotate': Path('/etc/logrotate.d/xocrange'),
              'journal-policy': Path('/etc/systemd/journald.conf.d/70-xocrange.conf'),
              'rsyslog-sysmon': Path('/etc/rsyslog.d/30-xocrange-sysmon.conf')}
MAX_MEMBERS = 1000000


def command(args, *, timeout=120, check=True):
    try:
        result = subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise XocError('operation_command', 'An appliance operation could not finish; consult its operation journal.') from exc
    if check and result.returncode:
        raise XocError('operation_command', 'An appliance command failed; the operation journal retains the recovery point.')
    return result


def timestamp():
    return datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')


def save(path, value):
    atomic(path, (json.dumps(value, indent=2, sort_keys=True)+'\n').encode())


def private(path, *, exists=True):
    path = Path(path).absolute()
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise XocError('unsafe_operation_path', 'Operation paths cannot traverse symlinks.')
    if exists and (not path.exists() or path.stat().st_uid != os.geteuid() or path.stat().st_mode & 0o077):
        raise XocError('unsafe_operation_path', 'Backup data must be owned by this administrator and private (0700/0600).')
    return path


@contextmanager
def operation_lock(wait=120, path='/run/lock/xocrange-install.lock'):
    """Serialize appliance operations.

    Log maintenance takes this lock for about a second every minute, so an
    operator command waits briefly instead of failing on that overlap; the
    periodic job itself passes wait=0 and skips a busy minute.
    """
    if os.geteuid() != 0:
        raise XocError('root_required', 'Appliance operations require sudo.')
    with Path(path).open('a') as stream:
        deadline = time.monotonic() + wait
        while True:
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError as exc:
                if time.monotonic() >= deadline:
                    raise XocError('operation_busy', 'Another installation, backup or restore is running.') from exc
                time.sleep(1)
        yield


def installed():
    value = json.loads((STATE/'last-install.json').read_text())
    release = Path(value['release'])
    if value.get('status') != 'installed' or release.parent != PREFIX/'releases' or not re.fullmatch('[a-f0-9]{64}', release.name):
        raise XocError('installation_state', 'A verified installed release is required.')
    if not re.fullmatch(r'install-[a-f0-9]{64}', value['plan']):
        raise XocError('installation_state', 'Invalid installed plan identity.')
    private(STATE)
    return value


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(4*1024*1024), b''):
            digest.update(block)
    return digest.hexdigest()


def volume_paths():
    names = command(['docker', '--context', 'default', 'volume', 'ls', '--filter', 'label=com.docker.compose.project='+PROJECT, '--format', '{{.Name}}']).stdout.splitlines()
    wanted = {}
    for name in names:
        if not name.startswith(PROJECT+'_'):
            raise XocError('volume_identity', 'An appliance volume has an unexpected name.')
        short = name[len(PROJECT)+1:]
        if not re.fullmatch('[a-z][a-z0-9-]{0,63}', short):
            raise XocError('volume_identity', 'Invalid volume identity.')
        if short.endswith('-socket') or short == 'platform-observation':
            continue
        wanted[name] = short
    # One inspect for all volumes: log maintenance calls this every minute and
    # each Docker CLI process is also a host Sysmon observation.
    items = json.loads(command(['docker', '--context', 'default', 'volume', 'inspect', *wanted]).stdout) if wanted else []
    if sorted(item.get('Name') for item in items) != sorted(wanted):
        raise XocError('volume_identity', 'Volume inspection differs from the listed appliance volumes.')
    result = {}
    for item in items:
        short = wanted[item['Name']]
        path = Path(item['Mountpoint']); labels = item.get('Labels') or {}
        if item.get('Driver') != 'local' or item.get('Options') or labels.get('com.docker.compose.project') != PROJECT or labels.get('com.docker.compose.volume') != short or any(p.is_symlink() for p in (path, *path.parents)):
            raise XocError('volume_identity', 'Refusing to back up an unrelated or redirected volume.')
        result[short] = path
    return result


def image_inventory(state):
    from .documents import yaml_document
    directory = Path(state['release'])/'.local/plans'/state['plan']
    compose = yaml_document(directory/'compose.yaml')
    locked = json.loads((directory/'images.lock.json').read_text())['services'] if (directory/'images.lock.json').exists() else {}
    images = {}
    for service, definition in compose['services'].items():
        reference = definition.get('image', PROJECT+'-'+service)
        item, = json.loads(command(['docker', '--context', 'default', 'image', 'inspect', locked.get(service, {}).get('id', reference)]).stdout)
        images[service] = {'id': item['Id'], 'reference': reference, 'repo_digests': sorted(item.get('RepoDigests') or [])}
    return images


def active_units():
    return [unit for unit in UNITS if command(['systemctl', 'is-active', '--quiet', unit], check=False).returncode == 0]


def stop():
    # Stop the producers before the collector and containers. auditd remains host-owned.
    # The evidence service reads the installed plan: stop it with the release it serves.
    for unit in ('xocrange-log-maintenance.timer', 'xocrange-log-maintenance.service', 'xocrange-observer.timer', 'xocrange-observer.service', 'xocrange-evidence.service', 'sysmon.service', 'xocrange-osquery.service', 'xocrange-collector.service', 'xocrange-core.service'):
        if command(['systemctl', 'show', unit, '-p', 'LoadState', '--value'], check=False).stdout.strip() == 'loaded':
            command(['systemctl', 'stop', unit], timeout=300)
    running = command(['docker', '--context', 'default', 'ps', '-q', '--filter', 'label=com.docker.compose.project='+PROJECT]).stdout.split()
    if running:
        command(['docker', '--context', 'default', 'stop', '--time', '60', *running], timeout=180)


def resume(units):
    command(['systemctl', 'daemon-reload'])
    for unit in ('xocrange-core.service', 'sysmon.service', 'xocrange-osquery.service', 'xocrange-collector.service', 'xocrange-evidence.service', 'xocrange-observer.service', 'xocrange-observer.timer', 'xocrange-log-maintenance.timer'):
        if unit in units:
            command(['systemctl', 'start', unit], timeout=600)


def pack(source, output):
    def accept(member):
        if member.isfile() or member.isdir() or member.issym() or member.islnk():
            return member
        return None  # Runtime sockets/devices are recreated by their owners.
    with tarfile.open(output, 'w:gz', compresslevel=1, dereference=False) as archive:
        archive.add(source, arcname='data', filter=accept)
    output.chmod(0o600)


def members(archive):
    entries = archive.getmembers()
    if len(entries) > MAX_MEMBERS:
        raise XocError('backup_archive', 'Archive member limit exceeded.')
    names, links = set(), set()
    for item in entries:
        path = PurePosixPath(item.name)
        if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0] != 'data' or str(path) != item.name.rstrip('/') or item.name in names:
            raise XocError('backup_archive', 'Invalid or duplicate archive path.')
        if not (item.isdir() or item.isfile() or item.issym() or item.islnk()) or item.size < 0:
            raise XocError('backup_archive', 'Unsupported archive entry.')
        if item.islnk():
            link = PurePosixPath(item.linkname)
            if link.is_absolute() or '..' in link.parts or not link.parts or link.parts[0] != 'data':
                raise XocError('backup_archive', 'A hard link escapes the backup.')
        names.add(item.name)
        if item.issym() or item.islnk():
            links.add(path)
    if any(any(parent in links for parent in PurePosixPath(item.name).parents) for item in entries):
        raise XocError('backup_archive', 'Archive entries cannot traverse links.')
    if 'data' not in names:
        raise XocError('backup_archive', 'Archive root is missing.')
    by_name = {item.name:item for item in entries}
    if not (by_name['data'].isdir() or by_name['data'].isfile()):
        raise XocError('backup_archive', 'Archive root cannot be a link.')
    for item in entries:
        if item.islnk() and (item.linkname not in by_name or not by_name[item.linkname].isfile()):
            raise XocError('backup_archive', 'Hard links must refer directly to an archived regular file.')
    return entries


def unpack(archive_path, destination):
    """Extract regular content first, then links. Never tar.extract/all as root."""
    destination.mkdir(mode=0o700)
    with tarfile.open(archive_path, 'r:gz') as archive:
        entries = members(archive)
        for item in entries:
            target = destination/item.name
            if item.issym():
                continue
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if item.isdir():
                target.mkdir(exist_ok=True, mode=0o700)
            else:
                # Hard links are materialized as regular bytes from the archive.
                with archive.extractfile(item) as source, target.open('xb') as output:
                    shutil.copyfileobj(source, output, 4*1024*1024)
        for item in entries:
            if item.issym():
                target = destination/item.name
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                target.symlink_to(item.linkname)
        for item in reversed(entries):
            target = destination/item.name
            os.chown(target, item.uid, item.gid, follow_symlinks=False)
            if not item.issym():
                target.chmod(item.mode & (0o3777 if item.isdir() else 0o1777))
                os.utime(target, (item.mtime, item.mtime), follow_symlinks=False)
    return destination/'data'


def paths(state, volumes):
    release = Path(state['release'])
    result = {'source': release, 'venv': PREFIX/'venvs'/release.name}
    result.update({'state-'+n: STATE/n for n in STATE_NAMES if (STATE/n).exists()})
    result.update({'host-'+n: p for n, p in HOST_PATHS.items() if p.exists()})
    result.update({'unit-'+u: Path('/etc/systemd/system')/u for u in OWNED_UNITS if (Path('/etc/systemd/system')/u).is_file()})
    result.update({'volume-'+n: p for n, p in volumes.items()})
    return result


def size_of(path):
    if path.is_file():
        return path.stat().st_size
    total = 0
    for base, dirs, files in os.walk(path, followlinks=False):
        for name in files:
            item = Path(base)/name
            if not item.is_symlink() and item.is_file():
                total += item.stat().st_size
    return total


def cursor_bindings(volumes):
    path = STATE/'siem/events.sqlite3'
    if not path.exists():
        return []
    with sqlite3.connect('file:'+str(path)+'?mode=ro', uri=True) as db:
        cursors = {name:json.loads(value) for name,value in db.execute('SELECT name,value FROM cursors') if re.search(r':\d+:\d+$', name)}
    result = []
    for volume, directory in volumes.items():
        for path in directory.rglob('*'):
            if path.is_file() and not path.is_symlink():
                info = path.stat(); suffix = f':{info.st_dev}:{info.st_ino}'
                for name, state in cursors.items():
                    compressed_match = path.suffix=='.gz' and state.get('file')==str(path).removesuffix('.gz')
                    if (name.endswith(suffix) or compressed_match) and ':'+PROJECT+'_'+volume+':' in name:
                        result.append({'cursor':name, 'volume':volume, 'relative':str(path.relative_to(directory))})
    return result


def rebase_cursors(value, volumes):
    path = STATE/'siem/events.sqlite3'
    if not path.exists():
        return
    with sqlite3.connect(path) as db:
        previous = dict(db.execute('SELECT name,value FROM cursors'))
        rebound = set()
        for item in value.get('cursor_bindings', []):
            relative = PurePosixPath(item['relative'])
            if relative.is_absolute() or '..' in relative.parts or item['volume'] not in volumes:
                raise XocError('backup_cursor', 'Invalid restored cursor path.')
            file = volumes[item['volume']]/relative
            if file.is_symlink() or not file.is_file() or item['cursor'] not in previous:
                continue
            info = file.stat(); old = item['cursor']; key = old.rsplit(':', 2)[0]+f':{info.st_dev}:{info.st_ino}'
            state = json.loads(previous[old]); state['file'] = str(file).removesuffix('.gz')
            if file.suffix == '.gz' and state.get('complete'):
                state['compressed_signature'] = [info.st_ino, info.st_size, info.st_mtime_ns]
            db.execute('INSERT OR REPLACE INTO cursors VALUES (?,?)', (key, json.dumps(state)))
            if old != key: rebound.add(old)
        for name in rebound:
            db.execute('DELETE FROM cursors WHERE name=?', (name,))
        journal = json.loads(previous['sysmon-journal']) if 'sysmon-journal' in previous else None
        same_host = value.get('machine_id') == Path('/etc/machine-id').read_text().strip()
        if journal:
            # Journal cursor IDs are machine-local. Time fallback replays stable
            # IDs on the same host; a replacement host starts at its own history.
            db.execute('DELETE FROM cursors WHERE name=?', ('sysmon-journal',))
            marker = {'since':max(0, int(journal.get('source_time', 0))-1) if same_host else 0,
                      'reason':'backup_restore', 'same_host':same_host}
            db.execute('INSERT OR REPLACE INTO cursors VALUES (?,?)', ('sysmon-journal-resume', json.dumps(marker)))


def create(output, *, portable=True, keep_stopped=False):
    state = installed(); output = private(output, exists=False)
    if output.exists():
        raise XocError('backup_exists', 'Choose a new backup directory.')
    volumes = volume_paths()
    sources = paths(state, volumes)
    if any(output == p or output.is_relative_to(p) for p in sources.values() if p.is_dir()):
        raise XocError('backup_recursion', 'Backups must be outside all archived data paths.')
    images = image_inventory(state)
    from .image_lock import retain
    retain(images)
    estimate = sum(size_of(p) for p in sources.values())
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if shutil.disk_usage(output.parent).free < estimate * 1.1 + 4*1024**3:
        raise XocError('backup_space', 'Insufficient free space for a consistent backup; services have not been stopped.')
    output.mkdir(mode=0o700)
    units = active_units()
    metadata = {'schema_version':'xoc.backup/0.1.0', 'created_at':timestamp(), 'status':'writing',
                'installation':state, 'units':units, 'images':images, 'portable':portable, 'files':{}}
    save(output/'journal.json', metadata)
    stopped = False
    try:
        stopped = True; stop()
        metadata['machine_id'] = Path('/etc/machine-id').read_text().strip()
        metadata['cursor_bindings'] = cursor_bindings(volumes)
        for name, source in sources.items():
            destination = output/(name+'.tar.gz')
            pack(source, destination)
            metadata['files'][destination.name] = {'sha256':sha256(destination), 'bytes':destination.stat().st_size, 'expanded_bytes':size_of(source)}
        if portable:
            image_file = output/'images.tar'
            command(['docker', '--context', 'default', 'image', 'save', '-o', image_file, *sorted({i['id'] for i in images.values()})], timeout=1800)
            image_file.chmod(0o600)
            metadata['files'][image_file.name] = {'sha256':sha256(image_file), 'bytes':image_file.stat().st_size, 'expanded_bytes':image_file.stat().st_size}
        metadata['status'] = 'complete'
        save(output/'manifest.json', metadata)
        (output/'journal.json').unlink()
    finally:
        if stopped and (not keep_stopped or metadata['status'] != 'complete'):
            resume(units)
    return {'status':'complete', 'path':str(output), 'archives':len(metadata['files']), 'bytes':sum(v['bytes'] for v in metadata['files'].values()), 'portable':portable}


def prune_checkpoints(current, backups=None):
    """Keep only the checkpoint of the install that just completed.

    Pre-install checkpoints were never removed; each copies all appliance
    state (14-23 GB on the development VM), so a few updates filled the disk.
    Manual backups (any other name) and points named by an unfinished
    operation journal are never touched.
    """
    base = Path(backups or STATE/'backups')
    current = Path(current).resolve()
    if current.parent != base.resolve() or not re.fullmatch(r'before-install-\d{8}T\d{6}-\d+', current.name) or not (current/'manifest.json').is_file():
        raise XocError('prune_checkpoint', 'Only a completed installer checkpoint can replace older ones.')
    protected = {current}
    for name in ('restore-operation.json', 'install-operation.json'):
        try:
            value = json.loads((base.parent/name).read_text())
        except (OSError, ValueError):
            continue
        if value.get('status') in ('staging', 'restoring', 'failed', 'in-progress', 'recovery-required'):
            protected |= {Path(v).resolve() for k, v in value.items() if k in ('recovery', 'checkpoint', 'backup') and isinstance(v, str)}
    removed = []
    for candidate in sorted(base.iterdir()):
        if candidate.is_symlink() or not candidate.is_dir() or candidate.resolve() in protected:
            continue
        if re.fullmatch(r'before-install-\d{8}T\d{6}-\d+', candidate.name):
            shutil.rmtree(candidate); removed.append(candidate.name)
    return {'status': 'pruned', 'kept': current.name, 'removed': removed}


def verify_backup(directory):
    try:
        return _verify_backup(directory)
    except (KeyError, TypeError, ValueError, tarfile.TarError) as exc:
        if isinstance(exc, XocError):
            raise
        raise XocError('backup_manifest', 'The backup structure is invalid.') from exc


def _verify_backup(directory):
    directory = private(directory)
    manifest = private(directory/'manifest.json')
    if manifest.stat().st_size > 1024*1024:
        raise XocError('backup_manifest', 'Backup manifest is too large.')
    value = json.loads(manifest.read_text())
    if value.get('schema_version') != 'xoc.backup/0.1.0' or value.get('status') != 'complete' or not isinstance(value.get('files'), dict):
        raise XocError('backup_manifest', 'A complete supported backup is required.')
    state = value['installation']; release = Path(state['release'])
    if release.parent != PREFIX/'releases' or not re.fullmatch('[a-f0-9]{64}', release.name) or not re.fullmatch(r'install-[a-f0-9]{64}', state['plan']):
        raise XocError('backup_manifest', 'Invalid backup release identity.')
    allowed = {'source', 'venv'} | {'state-'+n for n in STATE_NAMES} | {'host-'+n for n in HOST_PATHS} | {'unit-'+n for n in OWNED_UNITS}
    files = value['files']
    if len(files) > 256:
        raise XocError('backup_manifest', 'Too many backup archives.')
    if not {'source.tar.gz','venv.tar.gz','state-last-install.json.tar.gz'} <= set(files) or set(p.name for p in directory.iterdir()) != set(files)|{'manifest.json'}:
        raise XocError('backup_manifest', 'Backup files do not match the manifest.')
    for name, info in files.items():
        if set(info) != {'sha256','bytes','expanded_bytes'} or not re.fullmatch('[a-f0-9]{64}', info['sha256']) or any(type(info[k]) is not int or info[k] < 0 for k in ('bytes','expanded_bytes')):
            raise XocError('backup_manifest', 'Invalid backup size or checksum metadata.')
        stem = name.removesuffix('.tar.gz')
        if name != 'images.tar' and (not name.endswith('.tar.gz') or not (stem in allowed or re.fullmatch(r'volume-[a-z][a-z0-9-]{0,63}', stem))):
            raise XocError('backup_manifest', 'Unexpected backup archive.')
        path = private(directory/name)
        if not path.is_file() or path.stat().st_size != info['bytes'] or sha256(path) != info['sha256']:
            raise XocError('backup_checksum', 'Backup checksum verification failed before any service changes.')
        if name.endswith('.tar.gz'):
            with tarfile.open(path, 'r:gz') as archive:
                entries = members(archive)
                if sum(item.size for item in entries) > info['expanded_bytes'] + 1024**2:
                    raise XocError('backup_size', 'Archive exceeds its declared expansion budget.')
    if value['portable'] and 'images.tar' not in files:
        raise XocError('backup_images', 'Portable backup images are missing.')
    if set(value['units']) - set(UNITS):
        raise XocError('backup_manifest', 'Unexpected service in backup.')
    for service, image in value.get('images', {}).items():
        if not re.fullmatch('[a-z][a-z0-9-]{0,63}', service) or not re.fullmatch(r'sha256:[a-f0-9]{64}', image['id']) or not re.fullmatch('[a-z0-9][a-z0-9./_:@-]{0,240}', image['reference']):
            raise XocError('backup_images', 'Invalid saved image identity.')
    for item in value.get('cursor_bindings', []):
        path = PurePosixPath(item['relative'])
        if path.is_absolute() or '..' in path.parts or 'volume-'+item['volume']+'.tar.gz' not in files or not re.fullmatch(r'[a-z0-9:_-]+:\d+:\d+', item['cursor']):
            raise XocError('backup_cursor', 'Invalid saved source cursor.')
    return value


def target_for(name, state, volumes):
    if name == 'source': return Path(state['release'])
    if name == 'venv': return PREFIX/'venvs'/Path(state['release']).name
    if name.startswith('state-'): return STATE/name[6:]
    if name.startswith('host-'): return HOST_PATHS[name[5:]]
    if name.startswith('unit-'): return Path('/etc/systemd/system')/name[5:]
    if name.startswith('volume-'): return volumes[name[7:]]
    raise XocError('backup_manifest', 'Unexpected restore target.')


def replace_tree(source, target):
    if any(p.is_symlink() for p in (target, *target.parents)):
        raise XocError('restore_path', 'A restore destination traverses a symlink.')
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    staging = target.with_name('.xoc-restore-'+target.name)
    if staging.is_symlink():
        raise XocError('restore_path', 'Restore staging cannot be a symlink.')
    if staging.exists():
        staging.rename(target.with_name('.xoc-interrupted-'+timestamp()+'-'+target.name))
    if source.is_dir(): shutil.copytree(source, staging, symlinks=True, copy_function=shutil.copy2)
    else: shutil.copy2(source, staging)
    # copytree does not preserve numeric ownership; retain it explicitly.
    for original in [source, *source.rglob('*')] if source.is_dir() else [source]:
        copied = staging / original.relative_to(source) if original != source else staging
        info = original.lstat(); os.chown(copied, info.st_uid, info.st_gid, follow_symlinks=False)
    if target.is_dir(): shutil.rmtree(target)
    else: target.unlink(missing_ok=True)
    staging.rename(target)


def preserve_failed_state(state):
    """Retain writes made after a failed update; never discard incident evidence."""
    directory = STATE/'failed-state'/timestamp()
    directory.mkdir(parents=True, mode=0o700)
    files = {}
    for name, source in paths(state, volume_paths()).items():
        if not name.startswith(('state-', 'volume-')):
            continue
        target = directory/(name+'.tar.gz'); pack(source, target)
        files[target.name] = {'sha256':sha256(target), 'bytes':target.stat().st_size}
    save(directory/'evidence.json', {'status':'preserved', 'created_at':timestamp(), 'files':files})
    return directory


def restore(directory, *, checkpoint=True):
    value = verify_backup(directory); directory = Path(directory)
    try:
        current = installed()
    except (OSError, ValueError, KeyError):
        # Recovery can resume after interruption between unlink and rename of
        # last-install.json. The configured storage identity still must match.
        if checkpoint or (STATE/'storage-configured').read_text().strip() != value['installation']['data_directory']:
            raise
        current = value['installation']
    if current['data_directory'] != value['installation']['data_directory']:
        raise XocError('restore_storage', 'Install using the backup data directory before restoring.')
    expanded = sum(i['expanded_bytes'] for n, i in value['files'].items() if n != 'images.tar')
    if shutil.disk_usage(STATE).free < expanded * 2.2 + 4*1024**3:
        raise XocError('restore_space', 'Insufficient free space to stage and recover the restore.')
    recovery = STATE/'backups'/('before-restore-'+timestamp()) if checkpoint else None
    if recovery:
        create(recovery, portable=False)
    # A recovery run (checkpoint=False) restores a recovery point itself; keep
    # that point in the journal so a failed or interrupted run stays resumable.
    recovery_ref = str(recovery) if recovery else (None if checkpoint else str(directory))
    journal = STATE/'restore-operation.json'
    save(journal, {'status':'staging', 'backup':str(directory), 'recovery':recovery_ref})
    staging = Path(tempfile.mkdtemp(prefix='restore-', dir=STATE))
    mutated = False
    try:
        extracted = {}
        for name in value['files']:
            if name.endswith('.tar.gz'):
                key = name[:-7]
                extracted[key] = unpack(directory/name, staging/key)
        if value['portable']:
            command(['docker', '--context', 'default', 'image', 'load', '-i', directory/'images.tar'], timeout=1800)
        for item in value['images'].values():
            if not re.fullmatch(r'sha256:[0-9a-f]{64}', item['id']):
                raise XocError('backup_images', 'Invalid image identity.')
            command(['docker', '--context', 'default', 'image', 'inspect', item['id']])
        from .image_lock import retain
        retain(value['images'])
        mutated = True; stop()
        failed_state = preserve_failed_state(current) if not checkpoint else None
        save(journal, {'status':'restoring', 'backup':str(directory), 'recovery':recovery_ref,
                       'preserved_failed_state':str(failed_state) if failed_state else None})
        from .lab import Docker
        from .ui_setup import owned_volume
        engine = Docker(Path(current['release'])/'.local/plans'/current['plan']/'compose.yaml', PROJECT)
        volumes = {name[7:]:owned_volume(engine, PROJECT, name[7:]) for name in extracted if name.startswith('volume-')}
        for name, source in extracted.items():
            replace_tree(source, target_for(name, value['installation'], volumes))
        rebase_cursors(value, volumes)
        for unit in OWNED_UNITS:
            if 'unit-'+unit not in extracted:
                command(['systemctl', 'disable', unit], check=False)
                (Path('/etc/systemd/system')/unit).unlink(missing_ok=True)
        # The rsyslog Sysmon filter is kept even when an older backup lacks it:
        # it only removes a duplicate of the journald copy the collector reads.
        for name in ('logrotate', 'journal-policy', 'audit-rule'):
            if 'host-'+name not in extracted:
                HOST_PATHS[name].unlink(missing_ok=True)
        ops_journal = HOST_PATHS['journal-policy']
        if ops_journal.parent.exists():
            command(['systemctl', 'restart', 'systemd-journald'])
        command(['systemctl', 'try-restart', 'rsyslog.service'], check=False)
        # Legacy releases use tags. Rebind only the exact saved references to IDs.
        for item in value['images'].values():
            if '@' not in item['reference']:
                command(['docker', '--context', 'default', 'tag', item['id'], item['reference']])
        current_link = PREFIX/'current'
        if current_link.exists() and not current_link.is_symlink():
            raise XocError('restore_path', 'Unexpected current release pointer.')
        current_link.unlink(missing_ok=True); current_link.symlink_to(value['installation']['release'])
        resume(value['units'])
        save(journal, {'status':'complete', 'backup':str(directory), 'recovery':recovery_ref,
                       'preserved_failed_state':str(failed_state) if failed_state else None, 'finished_at':timestamp()})
    except BaseException:
        # Nothing was changed before mutation; mark it non-recoverable so a later
        # `xoc recover` cannot roll the host back to this stale checkpoint.
        status = 'failed' if mutated or not checkpoint else 'aborted'
        save(journal, {'status':status, 'backup':str(directory), 'recovery':recovery_ref})
        if mutated and recovery:
            restore(recovery, checkpoint=False)
            save(journal, {'status':'rolled-back', 'failed_backup':str(directory), 'recovery':str(recovery)})
        raise
    finally:
        shutil.rmtree(staging)
    return {'status':'restored', 'release':value['installation']['release'], 'backup':str(directory), 'recovery':str(recovery) if recovery else None}


def recover():
    """Explicitly resume the durable recovery point after process/host interruption."""
    missing = False
    for name, key in (('restore-operation.json','recovery'), ('install-operation.json','checkpoint')):
        path = STATE/name
        if not path.exists():
            continue
        private(path)
        value = json.loads(path.read_text())
        if value.get('status') not in ('staging','restoring','failed','in-progress','recovery-required'):
            continue
        if not value.get(key):
            missing = True
            continue
        result = restore(Path(value[key]), checkpoint=False)
        save(path, dict(value, status='recovered', recovered_at=timestamp()))
        return result
    if missing:
        raise XocError('recovery_point_missing', 'The interrupted operation has no completed recovery point.')
    return {'status':'no-recovery-needed'}
