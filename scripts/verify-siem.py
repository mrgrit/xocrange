#!/usr/bin/env python3
"""Installation acceptance: actual source files -> C1 -> Wazuh -> durable search."""
import json
from pathlib import Path
import subprocess
import sys
import time

from xocrange.event_store import Store, now
from xocrange.lab import Docker, checked_plan
from xocrange.events import SOURCES

store = Store('/var/lib/xocrange/siem')
cutoff = now()
plan_dir, result = checked_plan(Path(sys.argv[1]), sys.argv[2])
engine = Docker(plan_dir / 'compose.yaml', result['compose']['name'])
for options in ([], ['--port', '8081'], ['--marker', 'waf-block'], ['--marker', 'ips-block']):
    engine.run(['exec', '-T', 'lab-client', 'python', '-B', '/app/probe.py', *options], compose=True)
subprocess.run(['/usr/bin/true'], check=True)  # xoc_probe audit rule and Sysmon process event
deadline = time.monotonic() + 180
expected = set(SOURCES)
while True:
    report = store.status()
    available = {row[0] for row in store.db.execute("SELECT DISTINCT producer FROM events WHERE observed>=? AND confirmed IS NOT NULL AND julianday(json_extract(event, '$.timestamp'))>=julianday(?) AND (producer!='sysmon' OR json_extract(event, '$.event.type')='observation') AND (producer!='auditd' OR json_extract(event, '$.audit.key')='xoc_probe')", (cutoff,cutoff))}
    sources_ready = {row['source']: row['status'] for row in report['sources']}
    passed = expected <= available and sources_ready.get('wazuh') == 'ready'
    if passed or time.monotonic() >= deadline:
        result = {'status': 'passed' if passed else 'failed',
                  'checks': {source: source in available for source in SOURCES},
                  'store': report, 'since': cutoff, 'scope': 'Live local source records decoded by Wazuh; no dashboard/indexer acceptance.'}
        Path('/var/lib/xocrange/siem-acceptance.json').write_text(json.dumps(result, indent=2)+'\n')
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if passed else 2)
    time.sleep(3)
