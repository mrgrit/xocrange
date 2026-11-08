"""Rename device logs, reopen writers, and retain unread generations for SIEM."""
import json
import os
from pathlib import Path
import re
import sqlite3
import time
from . import operations as ops

LIMIT = 32*1024**2
MAX_AGE = 86400
SOURCES = {'fw-logs':('events.log',), 'ips-logs':('eve.json',),
           'web-logs':('access.log','error.log','modsec_audit.json')}


def history(path):
    path = Path(path)
    return sorted((p for p in path.parent.glob(path.name+'.xoc-*')
                   if re.fullmatch(re.escape(path.name)+r'\.xoc-\d{20}', p.name) and p.is_file() and not p.is_symlink()),
                  key=lambda p:p.stat().st_mtime_ns)


def open_inodes():
    opened = set()
    for process in Path('/proc').glob('[0-9]*'):
        try:
            for fd in (process/'fd').iterdir():
                try:
                    info = fd.stat(); opened.add((info.st_dev, info.st_ino))
                except OSError:
                    pass
        except OSError:
            pass
    return opened


def removable(path, states, opened, *, now=None, siem=True):
    info = path.stat()
    if (now or time.time())-info.st_mtime < MAX_AGE or (info.st_dev,info.st_ino) in opened:
        return False
    if not siem:
        return True
    suffix = f':{info.st_dev}:{info.st_ino}'
    return any(name.endswith(suffix) and not value.get('buffer') and value.get('offset',0) >= info.st_size for name,value in states.items())


def maintain():
    state = ops.installed(); selected = set(state['selected'])
    volumes = ops.volume_paths(); states = {}
    database = ops.STATE/'siem/events.sqlite3'
    if 'siem' in selected and database.exists():
        with sqlite3.connect('file:'+str(database)+'?mode=ro',uri=True) as db:
            states = {name:json.loads(value) for name,value in db.execute('SELECT name,value FROM cursors')}
    opened = open_inodes(); rotated = []; removed = []
    for volume, names in SOURCES.items():
        if volume not in volumes:
            continue
        for name in names:
            path = volumes[volume]/name
            if path.is_symlink():
                continue
            if path.exists() and path.stat().st_size >= LIMIT:
                target = path.with_name(path.name+'.xoc-'+str(time.time_ns()).zfill(20))
                path.rename(target); rotated.append((volume,name))
            for old in history(path):
                if removable(old, states, opened, siem='siem' in selected):
                    old.unlink(); removed.append(old.name)
    affected = {v for v,_ in rotated}
    if 'ips-logs' in affected:
        ops.command(['docker','--context','default','kill','--signal','HUP',ops.PROJECT+'-ips-1'])
    if 'web-logs' in affected:
        ops.command(['docker','--context','default','exec','--user','33:33',ops.PROJECT+'-web-1','apache2ctl','graceful'])
    return {'rotated':[n for _,n in rotated],'removed':len(removed),'unread_generations_preserved':True}
