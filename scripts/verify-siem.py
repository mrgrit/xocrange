#!/usr/bin/env python3
"""Installation acceptance: independent C1 and raw-source analysis routes."""
import json
from pathlib import Path
import subprocess
import sys
import time

from xocrange.event_store import Store, now
from xocrange.lab import Docker, checked_plan
from xocrange.events import SOURCES

store = Store('/var/lib/xocrange/siem')
plan_dir, result = checked_plan(Path(sys.argv[1]), sys.argv[2])
engine = Docker(plan_dir / 'compose.yaml', result['compose']['name'])
# A restored appliance can have durable input waiting from before maintenance.
# Drain it before generating a new timed probe; never skip a journal cursor or
# treat queued data as decoded. Brand-new installations normally pass immediately.
recovery_deadline = time.monotonic() + 900
last_notice = 0
while True:
    report = store.status()
    lag = report.get('sysmon_source_lag_seconds')
    caught_up = (lag is not None and lag < 90 and report['oldest_pending_seconds'] < 90
                 and report.get('oldest_native_input_pending_seconds', 0) < 90)
    if caught_up: break
    if time.monotonic() >= recovery_deadline:
        result = {'status':'failed', 'phase':'recovery-backlog', 'store':report,
                  'scope':'Retained input has not caught up; no data or cursor was skipped.'}
        Path('/var/lib/xocrange/siem-acceptance.json').write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(result,indent=2));raise SystemExit(2)
    if time.monotonic()-last_notice >= 30:
        print(json.dumps({'stage':'draining-retained-input','sysmon_lag_seconds':lag,
                          'pending':report['pending'],'native_pending':report.get('native_input_pending',0)}),flush=True)
        last_notice=time.monotonic()
    time.sleep(5)
cutoff = now()
for options in ([], ['--port', '8081'], ['--marker', 'waf-block'], ['--marker', 'ips-block']):
    engine.run(['exec', '-T', 'lab-client', 'python', '-B', '/app/probe.py', *options], compose=True)
subprocess.run(['/usr/bin/true'], check=True)  # xoc_probe audit rule and Sysmon process event
started = last_backlog = time.monotonic()
expected = set(SOURCES)
while True:
    report = store.status()
    # 180 s for fresh records; services restarted by the installation can queue a
    # burst of retained input right after the drain check, so allow up to 600 s
    # while that backlog is still being worked off. Nothing is skipped either way.
    backlog = (report['oldest_pending_seconds'] >= 30 or (report.get('sysmon_source_lag_seconds') or 0) >= 30
               or report.get('oldest_native_input_pending_seconds', 0) >= 30)
    if backlog: last_backlog = time.monotonic()
    deadline = max(started + 180, min(started + 600, last_backlog + 60))
    # Seek the recent interval for each producer. DISTINCT over the whole
    # multi-GiB evidence table makes acceptance itself starve live collection.
    available = {source for source in SOURCES if store.db.execute("SELECT 1 FROM events WHERE producer=? AND observed>=? AND confirmed IS NOT NULL AND julianday(json_extract(event, '$.timestamp'))>=julianday(?) AND (producer!='sysmon' OR json_extract(event, '$.event.type')='observation') AND (producer!='auditd' OR json_extract(event, '$.audit.key')='xoc_probe') ORDER BY observed DESC LIMIT 1", (source,cutoff,cutoff)).fetchone()}
    sources_ready = {row['source']: row['status'] for row in report['sources']}
    native = {source for source in SOURCES if store.db.execute("""SELECT 1 FROM native_inputs n INDEXED BY native_inputs_source_observed
        JOIN events e ON e.id=n.event_id WHERE n.source=? AND n.observed>=? AND n.confirmed IS NOT NULL
        AND n.error IS NULL AND n.decoder!='sensor-diagnostic'
        AND julianday(json_extract(e.event,'$.timestamp'))>=julianday(?)
        AND (n.source!='auditd' OR json_extract(e.event,'$.audit.key')='xoc_probe') ORDER BY n.observed DESC LIMIT 1""", (source,cutoff,cutoff)).fetchone()}
    passed = expected <= available and expected <= native and all(sources_ready.get(name) == 'ready' for name in ('wazuh','wazuh-native'))
    if passed or time.monotonic() >= deadline:
        result = {'status': 'passed' if passed else 'failed',
                  'checks': {source: source in available for source in SOURCES},
                  'native_checks': {source: source in native for source in SOURCES},
                  'store': report, 'since': cutoff, 'scope': 'Fresh local records: C1 alerts and independently decoded raw inputs with Manager archive receipts; dashboard/indexer acceptance is separate.'}
        Path('/var/lib/xocrange/siem-acceptance.json').write_text(json.dumps(result, indent=2)+'\n')
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if passed else 2)
    time.sleep(3)
