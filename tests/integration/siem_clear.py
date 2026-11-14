#!/usr/bin/env python3
"""Dedicated-VM acceptance: `xoc siem clear` starts the SIEM over.

Checks that the preview changes nothing; that the clear empties the evidence
store, search indices, Wazuh alert/archive logs and device logs with the
collector restarted; that all eight sources then pass the installer's SIEM
acceptance with no event or search document from before the clear (host logs
resume at their end); and that the status returns to ready. This REMOVES all
collected evidence on the VM.

sudo <release venv>/bin/python -I tests/integration/siem_clear.py <release> <plan> report.json
"""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import time

from xocrange.indexer import Client
from xocrange.lab import Docker

release, plan, output = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
STATE = Path('/var/lib/xocrange')
VOLUMES = STATE / 'data/docker/volumes'
PROJECT = 'xoc-core-security-path'
DEVICE = {'fw-logs': ['events.log'], 'ips-logs': ['eve.json'], 'web-logs': ['access.log', 'error.log', 'modsec_audit.json']}
engine = Docker(release / '.local/plans' / plan / 'compose.yaml', PROJECT)
indexer = Client(engine, PROJECT, user='admin')


def xoc(*args):
    run = subprocess.run(['xoc', *args], capture_output=True, text=True, timeout=900)
    return run.returncode, json.loads(run.stdout or run.stderr or '{}')


def db_counts():
    db = sqlite3.connect(f'file:{STATE}/siem/events.sqlite3?mode=ro', uri=True, timeout=30)
    try:
        return {t: db.execute(f'SELECT COUNT(*) FROM {t}').fetchone()[0] for t in ('records', 'events', 'wazuh_alerts')}
    finally:
        db.close()


def sizes():
    result = {f'{v}/{n}': (VOLUMES / f'{PROJECT}_{v}/_data' / n).stat().st_size for v, names in DEVICE.items() for n in names
              if (VOLUMES / f'{PROJECT}_{v}/_data' / n).exists()}
    for kind in ('alerts', 'archives'):
        path = VOLUMES / f'{PROJECT}_siem-logs/_data' / kind / f'{kind}.json'
        result[f'siem-logs/{kind}.json'] = path.stat().st_size
    return result


def indices():
    code, rows = indexer.request('GET', '/_cat/indices/xoc-events-*,wazuh-alerts-4.x-*?format=json&h=index,docs.count')
    return {r['index']: int(r['docs.count'] or 0) for r in rows} if code == 200 else {}


def older_docs(cutoff):
    total = 0
    for pattern, field in (('xoc-events-*', 'timestamp'), ('wazuh-alerts-4.x-*', 'timestamp')):
        code, body = indexer.request('POST', f'/{pattern}/_count?allow_no_indices=true',
                                     {'query': {'range': {field: {'lt': cutoff}}}})
        total += body.get('count', 0) if code == 200 else 10**9
    return total


checks = {}
before = {'db': db_counts(), 'sizes': sizes(), 'indices': indices()}
checks['had_data_before'] = before['db']['records'] > 0 and sum(before['indices'].values()) > 0

code, preview = xoc('siem', 'clear')
checks['preview_requires_confirmation'] = code == 0 and preview.get('status') == 'confirmation-required'
checks['preview_changed_nothing'] = db_counts()['records'] >= before['db']['records'] and indices().keys() == before['indices'].keys()

started = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
code, cleared = xoc('siem', 'clear', '--yes')
checks['clear_succeeded'] = code == 0 and cleared.get('status') == 'cleared'
checks['collector_restarted'] = subprocess.run(['systemctl', 'is-active', '--quiet', 'xocrange-collector']).returncode == 0
after = {'db': db_counts(), 'sizes': sizes(), 'indices': indices()}
checks['indices_deleted'] = cleared.get('search_indices_deleted', 0) >= 1
checks['device_logs_emptied'] = all(after['sizes'][k] < 65536 for k in after['sizes'] if not k.startswith('siem-logs'))
checks['manager_logs_emptied'] = all(after['sizes'][k] < before['sizes'][k] for k in after['sizes'] if k.startswith('siem-logs'))

# Fresh activity across all eight sources (the installer's own acceptance).
python = sys.executable
run = subprocess.run([python, str(release / 'scripts/verify-siem.py'), str(release), plan], capture_output=True, text=True, timeout=1500)
try:
    siem = json.loads(run.stdout[run.stdout.index('{\n'):])
except ValueError:
    siem = {'status': 'unparsable'}
checks['eight_sources_after_clear'] = run.returncode == 0 and siem.get('status') == 'passed'

db = sqlite3.connect(f'file:{STATE}/siem/events.sqlite3?mode=ro', uri=True, timeout=30)
# Every C1 event is about activity after the clear (host logs resumed at their end).
stale = db.execute("SELECT producer, COUNT(*) FROM events WHERE julianday(json_extract(event,'$.timestamp')) < julianday(?) - 0.0007 GROUP BY producer", (started,)).fetchall()
checks['no_events_from_before_clear'] = not stale
db.close()
time.sleep(60)
status = xoc('siem', 'status')[1]
checks['status_ready'] = status.get('status') == 'ready' and status.get('quarantined') == 0
# Same 60 s allowance as the database check: Sysmon resumes at the second the
# clear began, so it records the clear command's own processes.
margin = (datetime.fromisoformat(started.replace('Z', '+00:00')) - timedelta(seconds=60)).isoformat().replace('+00:00', 'Z')
checks['no_search_documents_from_before_clear'] = older_docs(margin) == 0
report = {'status': 'passed' if all(checks.values()) else 'failed', 'checks': checks, 'started': started,
          'before': before, 'after_clear': after, 'clear_result': cleared, 'stale_events': stale,
          'siem_status': {k: status.get(k) for k in ('status', 'pending', 'quarantined', 'index_pending')},
          'indices_after_activity': indices()}
output.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
