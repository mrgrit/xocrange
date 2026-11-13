#!/usr/bin/env python3
"""Dedicated-VM acceptance: concurrent console preview/apply through Core HTTPS.

Two separately logged-in admin sessions preview and apply against the real
firewall at the same moment, through the WAF, Core authentication, the DB
write lock and audit. concurrent_apply.py covers the same race at the device
broker without a login.

The test adds unused address objects (nft sets referenced by no rule) and
rolls the policy back; the firewall write policy is restored afterwards.

sudo XOC_ADMIN_PASSWORD_FILE=<0600 file> <release venv>/bin/python \
    tests/integration/concurrent_core.py <release> --output report.json
"""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import threading

from xocrange.platform_setup import STATE
from xocrange.ui_setup import private_json
from admin_credential import admin_password

API = '/core/api/console/fw'


def obj(name, address):
    return {'operation': 'upsert', 'kind': 'object', 'name': 'concurrency ' + name,
            'fields': {'name': 'xoc_concurrency_' + name, 'type': 'ipv4_addr', 'elements': address}}


def names(state):
    return sorted(o['fields']['name'] for o in state['objects'])


def together(*calls):
    results = [None] * len(calls)
    barrier = threading.Barrier(len(calls))

    def run(index):
        session, path, body = calls[index]
        barrier.wait()
        code, data, headers, _ = session.request(path, body)
        results[index] = (code, data, headers.get('X-Request-ID'))
    threads = [threading.Thread(target=run, args=(i,)) for i in range(len(calls))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return results


def verify(root, project):
    spec = importlib.util.spec_from_file_location('core_acceptance', root / 'scripts/verify-platform.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    secret = private_json(STATE / 'credentials.json')
    password = admin_password(secret)
    a, b = module.Session(secret['public_host']), module.Session(secret['public_host'])
    logins = [a.login('admin', password)[0], b.login('admin', password)[0]]
    checks = {'two_admin_sessions': logins == [200, 200]}
    if not checks['two_admin_sessions']:
        # 429: the per-account window (10 failed logins / 15 min) is spent.
        return {'status': 'failed', 'checks': checks, 'login_status': logins, 'winner': None,
                'finished_at': datetime.now(timezone.utc).isoformat(), 'scope': 'Login failed; nothing was changed.'}
    policy = next(p for p in a.request('/core/api/devices')[1]['devices'] if p['device'] == 'fw')
    unlocked = False
    winner = None
    try:
        if not policy['write_enabled']:
            unlocked = a.request('/core/api/devices/fw', {'write_enabled': True, 'version': policy['version']})[0] == 200
            checks['write_unlocked_for_test'] = unlocked
        start = a.request(API)[1]
        version, original = start['version'], names(start)
        checks['no_leftover_test_objects'] = not any(n.startswith('xoc_concurrency_') for n in original)
        # 1. Two admins preview the same revision at once; both validate.
        (pa, da, _), (pb, db, _) = together((a, API + '/preview', {'version': version, 'payload': obj('a', '192.0.2.10')}),
                                            (b, API + '/preview', {'version': version, 'payload': obj('b', '192.0.2.20')}))
        checks['concurrent_previews_validated'] = pa == 200 and pb == 200
        # 2. Both apply at once: exactly one 200, the other a 409 conflict.
        applies = together((a, API + '/apply', {'version': version, 'token': da.get('token', '')}),
                           (b, API + '/apply', {'version': version, 'token': db.get('token', '')}))
        codes = [code for code, _, _ in applies]
        checks['exactly_one_apply'] = sorted(codes) == [200, 409]
        after = a.request(API)[1]
        if codes.count(200) == 1:
            winner = 'ab'[codes.index(200)]
        checks['single_revision_step'] = after['version'] == version + 1
        checks['only_winner_object'] = bool(winner) and names(after) == sorted(original + ['xoc_concurrency_' + winner])
        # 3. A stale revision is refused through HTTPS as well.
        stale = a.request(API + '/apply', {'version': version, 'token': da.get('token', '')})
        checks['stale_apply_conflict'] = stale[0] == 409
        # 4. Audit: each racing request left its intent and its own outcome.
        events = a.request('/core/api/audit')[1]['events']
        outcomes = {}
        for event in events:
            if event['action'] == 'console_apply' and event['target'] == 'fw':
                outcomes.setdefault(event['request_id'], set()).add(event['outcome'])
        expected = [{'requested', 'applied'} if code == 200 else {'requested', 'rejected'} for code in codes]
        checks['audit_per_request'] = [outcomes.get(rid) for _, _, rid in applies] == expected
        checks['audit_actor'] = all(e['actor'] == 'admin' for e in events if e['request_id'] in {rid for _, _, rid in applies})
        # 5. Restore the starting policy with the device's own rollback.
        restore = a.request(API + '/preview', {'version': after['version'], 'payload': {'operation': 'rollback'}})
        applied = a.request(API + '/apply', {'version': after['version'], 'token': restore[1].get('token', '')}) if restore[0] == 200 else restore
        final = a.request(API)[1]
        checks['rolled_back'] = applied[0] == 200 and names(final) == original and final['version'] == version + 2
    finally:
        if unlocked:
            latest = next(p for p in a.request('/core/api/devices')[1]['devices'] if p['device'] == 'fw')
            checks['write_policy_restored'] = a.request('/core/api/devices/fw', {'write_enabled': False, 'version': latest['version']})[0] == 200
        a.request('/core/api/logout', {})
        b.request('/core/api/logout', {})
    nft = subprocess.run(['docker', '--context', 'default', 'exec', project + '-fw-1', 'nft', 'list', 'ruleset'],
                         capture_output=True, text=True, timeout=60).stdout
    checks['no_test_sets_in_running_ruleset'] = bool(nft) and 'xoc_concurrency_' not in nft
    return {'status': 'passed' if all(checks.values()) else 'failed', 'checks': checks, 'winner': winner,
            'finished_at': datetime.now(timezone.utc).isoformat(),
            'scope': 'Two admin sessions through HTTPS/WAF, Core authentication, DB write lock and audit, '
                     'against the real firewall broker.'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('root', type=Path)
    parser.add_argument('--project', default='xoc-core-security-path')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = verify(args.root, args.project)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'passed' else 2


if __name__ == '__main__':
    sys.exit(main())
