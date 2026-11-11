"""Explicit bounded local retention; pending evidence is never aged out."""
import json
import os
from pathlib import Path
import shutil
from .errors import XocError

DEFAULT = {'days': 1, 'ingest_bytes': 24*1024**3, 'database_bytes': 32*1024**3,
           'reserve_bytes': 2*1024**3, 'index_days': 7, 'archive_days': 2}


def policy(directory):
    path = Path(directory)/'retention.json'
    if not path.exists():
        return dict(DEFAULT)
    if path.is_symlink() or path.stat().st_mode & 0o077 or path.stat().st_uid != os.geteuid():
        raise XocError('unsafe_retention', 'Retention policy must be private and locally owned.')
    try:
        supplied = json.loads(path.read_text())
        if not isinstance(supplied, dict) or not supplied.keys() <= DEFAULT.keys(): raise ValueError()
        result = DEFAULT | supplied
        if any(type(v) is not int for v in result.values()): raise ValueError()
        if not 1 <= result['days'] <= 90 or not 1 <= result['archive_days'] <= 90 or not 1 <= result['index_days'] <= 365: raise ValueError()
        if not 1024**3 <= result['ingest_bytes'] <= result['database_bytes']-1024**3 <= 1024**4: raise ValueError()
        if not 256*1024**2 <= result['reserve_bytes'] <= 64*1024**3: raise ValueError()
        return result
    except (ValueError, OSError):
        raise XocError('invalid_retention', 'Retention limits are outside the supported range.')


def usage(store):
    size = store.db.execute('PRAGMA page_size').fetchone()[0]
    pages = store.db.execute('PRAGMA page_count').fetchone()[0]
    free = store.db.execute('PRAGMA freelist_count').fetchone()[0]
    return {'allocated_bytes': pages*size, 'used_bytes': (pages-free)*size,
            'filesystem_free_bytes': shutil.disk_usage(store.directory).free}


def check_write(store, *, analysis=False):
    used = usage(store)
    if used['filesystem_free_bytes'] < store.policy['reserve_bytes']:
        raise XocError('disk_reserve', 'Collection paused to preserve disk reserve; queued evidence remains intact.')
    budget = store.policy['database_bytes']-512*1024**2 if analysis else store.policy['ingest_bytes']
    if used['used_bytes'] >= budget:
        raise XocError('store_full', 'Local storage budget reached; unacknowledged input and cursors are retained.')


def retained_manager_paths(path):
    """Wazuh uses dated hard links, not .1/.2; accept only its exact layout."""
    path = Path(path)
    stem = 'ossec-alerts-' if path.name == 'alerts.json' else 'ossec-archive-' if path.name == 'archives.json' else None
    if stem is None:
        return []
    import re
    result = []
    for year in path.parent.iterdir():
        if year.is_symlink() or not year.is_dir() or not re.fullmatch(r'20\d\d', year.name): continue
        for month in year.iterdir():
            if month.is_symlink() or not month.is_dir() or month.name not in ('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'): continue
            for candidate in month.iterdir():
                if not candidate.is_symlink() and candidate.is_file() and re.fullmatch(stem+r'\d{2}(?:-\d{3})?\.json(?:\.gz)?', candidate.name):
                    result.append(candidate)
    return sorted(result, key=lambda p:(p.stat().st_mtime_ns,str(p)))


def remove_orphan_text(active, cutoff):
    """Drop closed text renditions whose JSON twin was already removed.

    The text copy is only deleted together with its JSON in the same pass, so
    a .log that was still too new at that moment stayed forever (122 MB of
    Nov 7 alerts on the development VM). The collector never reads .log files.
    """
    import re
    active = Path(active)
    stem = 'ossec-alerts-' if active.name == 'alerts.json' else 'ossec-archive-' if active.name == 'archives.json' else None
    if stem is None or not active.parent.is_dir():
        return 0
    removed = 0
    for year in active.parent.iterdir():
        if year.is_symlink() or not year.is_dir() or not re.fullmatch(r'20\d\d', year.name): continue
        for month in year.iterdir():
            if month.is_symlink() or not month.is_dir(): continue
            for text in month.iterdir():
                match = re.fullmatch(stem+r'(\d{2}(?:-\d{3})?)\.log(\.gz)?', text.name)
                if not match or text.is_symlink() or not text.is_file(): continue
                twin = [month/(stem+match[1]+'.json'+suffix) for suffix in ('', '.gz')]
                info = text.stat()
                if not any(t.exists() for t in twin) and info.st_nlink == 1 and info.st_mtime < cutoff:
                    text.unlink(); removed += 1
    return removed


def maintain(collector):
    """Remove only old, fully read, closed project archives and expired indices."""
    from datetime import datetime, timezone, timedelta
    import time
    import re
    store = collector.store
    deleted = 0
    name, mount, base = collector.volumes['siem']
    cutoff = time.time()-store.policy['archive_days']*86400
    for kind, source in [('alerts','wazuh-alerts'),('archives','wazuh-archives')]:
        for path in retained_manager_paths(mount/kind/(kind+'.json')):
            stat = path.stat()
            if stat.st_mtime >= cutoff or stat.st_nlink > 1: continue
            key = f'{source}:{name}:{stat.st_dev}:{stat.st_ino}'
            state = store.cursor(key)
            if path.suffix == '.gz':
                logical = str(path).removesuffix('.gz')
                state = next((json.loads(row[0]) for row in store.db.execute('SELECT value FROM cursors WHERE name LIKE ?', (source+':'+name+':%',)) if json.loads(row[0]).get('file') == logical), None)
            if state and not state.get('buffer') and (state.get('complete') if path.suffix=='.gz' else state.get('offset',0)>=stat.st_size):
                path.unlink();deleted += 1
                # The text rendition is redundant; only delete the same closed interval.
                text = Path(str(path).replace('.json','.log'))
                if text.is_file() and not text.is_symlink() and text.stat().st_nlink==1 and text.stat().st_mtime<cutoff:text.unlink()
        deleted += remove_orphan_text(mount/kind/(kind+'.json'), cutoff)
    if collector.indexer:
        from .indexer import Client
        admin = Client(collector.engine, collector.indexer.project, user='admin')
        status, rows = admin.request('GET','/_cat/indices/xoc-events-*,wazuh-alerts-4.x-*?format=json&h=index')
        if status != 200 or not isinstance(rows,list):raise XocError('retention_indices','Cannot inspect retention indices.')
        day = (datetime.now(timezone.utc)-timedelta(days=store.policy['index_days'])).date().isoformat()
        for row in rows:
            match = re.fullmatch(r'(xoc-events-|wazuh-alerts-4\.x-)(20\d\d)[.-](\d\d)[.-](\d\d)',row.get('index',''))
            if not match:continue
            date = '-'.join(match.groups()[1:])
            if date>=day:continue
            table = 'events' if match[1]=='xoc-events-' else 'wazuh_alerts'
            pending=store.db.execute(f'SELECT 1 FROM {table} WHERE indexed IS NULL AND observed>=? AND observed<? LIMIT 1',(date,date+'Z')).fetchone()
            if pending:continue
            code,_=admin.request('DELETE','/'+row['index'])
            if code not in (200,404):raise XocError('retention_delete','Indexer rejected retention deletion.')
    with store.transaction():
        store.set_cursor('retention-last',{'checked':time.time(),'closed_json_removed':deleted})
    return 'ready'
