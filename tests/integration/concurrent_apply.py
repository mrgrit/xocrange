#!/usr/bin/env python3
"""Dedicated-VM acceptance: concurrent preview/apply against one real device broker.

Requests go to the firewall broker socket as the platform's uid (65532) inside
the platform container, so the real serialization, version check and review
ticket of the device are exercised without a Core login. The Core HTTPS layer
(authentication, DB write lock, audit) is covered by device_console.py.

The test adds unused address objects (nft sets referenced by no rule), so
traffic is not affected, and rolls the policy back to the starting revision.

sudo python3 tests/integration/concurrent_apply.py --output report.json
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys

CLIENT = r'''
import json, socket, sys, threading
SOCKET = '/run/xoc-console-fw/api.sock'

def call(body):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(60); s.connect(SOCKET)
        s.sendall(json.dumps(body).encode() + b'\n')
        data = b''
        while not data.endswith(b'\n'):
            chunk = s.recv(65536)
            if not chunk: break
            data += chunk
    return json.loads(data)

def together(*bodies):
    results = [None] * len(bodies); barrier = threading.Barrier(len(bodies))
    def run(i):
        barrier.wait(); results[i] = call(bodies[i])
    threads = [threading.Thread(target=run, args=(i,)) for i in range(len(bodies))]
    [t.start() for t in threads]; [t.join() for t in threads]
    return results

def obj(name, address):
    return {'operation': 'upsert', 'kind': 'object', 'name': 'concurrency ' + name,
            'fields': {'name': 'xoc_concurrency_' + name, 'type': 'ipv4_addr', 'elements': address}}

def names(state):
    return sorted(o['fields']['name'] for o in state['objects'])

checks = {}
start = call({'action': 'status'})['data']; version = start['version']; original = names(start)
checks['no_leftover_test_objects'] = not any(n.startswith('xoc_concurrency_') for n in original)

# 1. Two operators preview the same revision at once: both validate, the later ticket wins.
a, b = together({'action': 'preview', 'version': version, 'actor': 'op-a', 'payload': obj('a', '192.0.2.10')},
                {'action': 'preview', 'version': version, 'actor': 'op-b', 'payload': obj('b', '192.0.2.20')})
checks['concurrent_previews_validated'] = a['ok'] and b['ok']
# 2. Both apply at once: exactly one succeeds, the other is a 409 conflict.
results = together({'action': 'apply', 'version': version, 'actor': 'op-a', 'token': a['data']['token']},
                   {'action': 'apply', 'version': version, 'actor': 'op-b', 'token': b['data']['token']})
winners = [i for i, r in enumerate(results) if r['ok']]
checks['exactly_one_apply'] = len(winners) == 1
checks['loser_is_conflict'] = all(r['status'] == 409 for r in results if not r['ok'])
after = call({'action': 'status'})['data']
winner = 'ab'[winners[0]] if winners else None
checks['single_revision_step'] = after['version'] == version + 1
checks['only_winner_object'] = names(after) == sorted(original + ['xoc_concurrency_' + winner]) if winner else False
# 3. A stale revision is refused for preview and apply.
stale_preview = call({'action': 'preview', 'version': version, 'actor': 'op-a', 'payload': obj('c', '192.0.2.30')})
stale_apply = call({'action': 'apply', 'version': version, 'actor': 'op-a', 'token': a['data']['token']})
checks['stale_preview_conflict'] = not stale_preview['ok'] and stale_preview['status'] == 409
checks['stale_apply_conflict'] = not stale_apply['ok'] and stale_apply['status'] == 409
# 4. A ticket replaced by another operator's newer preview cannot be applied.
first = call({'action': 'preview', 'version': after['version'], 'actor': 'op-a', 'payload': obj('d', '192.0.2.40')})
second = call({'action': 'preview', 'version': after['version'], 'actor': 'op-b', 'payload': obj('e', '192.0.2.50')})
replaced = call({'action': 'apply', 'version': after['version'], 'actor': 'op-a', 'token': first['data']['token']})
checks['replaced_ticket_conflict'] = first['ok'] and second['ok'] and not replaced['ok'] and replaced['status'] == 409
checks['replaced_ticket_left_policy_unchanged'] = call({'action': 'status'})['data']['version'] == after['version']
# 5. Restore the starting policy with the device's own rollback.
restore = call({'action': 'preview', 'version': after['version'], 'actor': 'op-a', 'payload': {'operation': 'rollback'}})
applied = call({'action': 'apply', 'version': after['version'], 'actor': 'op-a', 'token': restore['data']['token']}) if restore['ok'] else restore
final = call({'action': 'status'})['data']
checks['rolled_back'] = applied['ok'] and names(final) == original and final['version'] == version + 2
print(json.dumps({'checks': checks, 'start_version': version, 'winner': winner}))
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--project', default='xoc-core-security-path')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = subprocess.run(['docker', '--context', 'default', 'exec', '-i', '-u', '65532', args.project + '-platform-1',
                             'python3', '-I', '-'], input=CLIENT, capture_output=True, text=True, timeout=600)
    if result.returncode:
        raise SystemExit('Broker client failed: ' + result.stderr[-2000:])
    report = json.loads(result.stdout.strip().splitlines()[-1])
    nft = subprocess.run(['docker', '--context', 'default', 'exec', args.project + '-fw-1', 'nft', 'list', 'ruleset'],
                         capture_output=True, text=True, timeout=60).stdout
    report['checks']['no_test_sets_in_running_ruleset'] = 'xoc_concurrency_' not in nft
    report.update(status='passed' if all(report['checks'].values()) else 'failed',
                  finished_at=datetime.now(timezone.utc).isoformat(),
                  scope='Device broker serialization, version and review-ticket conflicts on the real firewall; '
                        'Core HTTPS authentication and DB write lock are not part of this check.')
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'passed' else 2


if __name__ == '__main__':
    sys.exit(main())
