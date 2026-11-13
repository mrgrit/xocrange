#!/usr/bin/env python3
"""Dedicated-VM acceptance: a client outside Docker keeps its source address.

A temporary network namespace and veth pair (documentation range
198.51.100.0/24) send an HTTPS request to the host's own address, so the
packet enters through a non-Docker interface like an external PC
(PREROUTING DNAT -> ingress -> fw -> IPS -> WAF). The ingress log, the WAF
access log and the SIEM C1 events must all carry the client address. The
namespace and veth are removed afterwards.

sudo python3 -I tests/integration/source_ip.py --output report.json
"""
import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
import uuid

STATE = Path('/var/lib/xocrange')
WEB_LOGS = STATE / 'data/docker/volumes/xoc-core-security-path_web-logs/_data'
NAMESPACE, HOST_LINK, CLIENT_LINK = 'xocsrc', 'xocsrc-h', 'xocsrc-n'
HOST_ADDRESS, CLIENT_ADDRESS = '198.51.100.1', '198.51.100.2'


def run(*args, check=True):
    return subprocess.run(list(args), capture_output=True, text=True, timeout=60, check=check)


def host_address():
    route = json.loads(run('ip', '-j', 'route', 'get', '1.1.1.1').stdout)[0]
    return route['prefsrc']


def cleanup():
    run('ip', 'netns', 'del', NAMESPACE, check=False)
    run('ip', 'link', 'del', HOST_LINK, check=False)


def verify(wait):
    public_host = json.loads((STATE / 'platform/credentials.json').read_text())['public_host']
    target = host_address()
    marker = 'xoc-source-ip-' + uuid.uuid4().hex[:12]
    started = datetime.now(timezone.utc) - timedelta(seconds=5)
    checks = {}
    cleanup()
    try:
        run('ip', 'netns', 'add', NAMESPACE)
        run('ip', 'link', 'add', HOST_LINK, 'type', 'veth', 'peer', 'name', CLIENT_LINK)
        run('ip', 'link', 'set', CLIENT_LINK, 'netns', NAMESPACE)
        run('ip', 'addr', 'add', HOST_ADDRESS + '/24', 'dev', HOST_LINK)
        run('ip', 'link', 'set', HOST_LINK, 'up')
        inside = ['ip', 'netns', 'exec', NAMESPACE]
        run(*inside, 'ip', 'addr', 'add', CLIENT_ADDRESS + '/24', 'dev', CLIENT_LINK)
        run(*inside, 'ip', 'link', 'set', CLIENT_LINK, 'up')
        run(*inside, 'ip', 'route', 'add', 'default', 'via', HOST_ADDRESS)
        code = run(*inside, 'curl', '-sk', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '20',
                   '--resolve', f'{public_host}:443:{target}', f'https://{public_host}/{marker}', check=False).stdout
        checks['request_answered'] = code.isdigit() and code != '000'
    finally:
        cleanup()
    checks['namespace_removed'] = NAMESPACE not in run('ip', 'netns', 'list').stdout
    time.sleep(2)
    lines = [line for path in WEB_LOGS.glob('*access*') if path.is_file()
             for line in path.read_text(errors='replace').splitlines() if marker in line]
    checks['waf_access_log_client'] = any(line.startswith(CLIENT_ADDRESS + ' ') for line in lines)
    checks['ingress_log_client'] = any(f' {CLIENT_ADDRESS} ' in line and not line.startswith(CLIENT_ADDRESS) for line in lines)
    checks['no_gateway_address'] = bool(lines) and not any('172.18.0.1' in line for line in lines)
    sources = {}
    deadline = time.monotonic() + wait
    db = sqlite3.connect(f'file:{STATE}/siem/events.sqlite3?mode=ro', uri=True, timeout=30)
    while time.monotonic() < deadline:
        rows = db.execute("SELECT e.producer, e.event FROM records r JOIN events e ON e.ref=r.ref "
                          "WHERE r.observed>=? AND r.source IN ('apache-access','modsecurity') AND instr(CAST(r.raw AS TEXT), ?)>0",
                          (started.isoformat().replace('+00:00', 'Z'), marker)).fetchall()
        sources = {}
        for producer, event in rows:
            sources.setdefault(producer, set()).add(json.loads(event).get('network', {}).get('source', {}).get('ip'))
        if {'apache-access', 'modsecurity'} <= set(sources):
            break
        time.sleep(5)
    for producer in ('apache-access', 'modsecurity'):
        checks['siem_' + producer.replace('-', '_') + '_client'] = sources.get(producer) == {CLIENT_ADDRESS}
    return {'status': 'passed' if all(checks.values()) else 'failed', 'checks': checks, 'client': CLIENT_ADDRESS,
            'target': target, 'siem_sources': {k: sorted(map(str, v)) for k, v in sources.items()},
            'finished_at': datetime.now(timezone.utc).isoformat(),
            'scope': 'Simulated external client via a non-Docker interface; a real external PC remains an RC re-run.'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--wait', type=int, default=120, help='seconds to wait for SIEM events')
    args = parser.parse_args()
    report = verify(args.wait)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'passed' else 2


if __name__ == '__main__':
    sys.exit(main())
