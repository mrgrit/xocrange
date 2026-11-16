#!/usr/bin/env python3
"""Keep this Core's /etc/hosts Live Fire block equal to the class domain list (ADR 0011).

Runs from a root timer that the installer creates only on a Core enrolled with a Live Fire
class code. It asks Range Control for the class list over the outbound gateway with the range
certificate (/etc/xocrange/livefire/credentials) and rewrites only the managed block
(# BEGIN XOC LAB DOMAINS ... # END XOC LAB DOMAINS); other hosts entries are kept. Only lab
names (.lab, .test, .internal, .home.arpa) on private IPv4 addresses are written. If Range
Control cannot be reached the existing block stays. Standard library only.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import ssl
import sys
import tempfile
import urllib.request
from pathlib import Path

CREDENTIALS = Path(os.environ.get('XOC_LIVEFIRE_CREDENTIALS', '/etc/xocrange/livefire/credentials'))
HOSTS = Path(os.environ.get('XOC_LIVEFIRE_HOSTS', '/etc/hosts'))
BEGIN, END = '# BEGIN XOC LAB DOMAINS', '# END XOC LAB DOMAINS'
LAB = re.compile(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:lab|test|internal|home\.arpa)\Z')


def block(entries) -> str:
    lines = []
    for entry in (entries or [])[:500]:
        try:
            address = ipaddress.IPv4Address(entry['address'])
        except (KeyError, TypeError, ValueError):
            continue
        if not address.is_private or address.is_loopback:
            continue
        names = [n for n in (entry.get('names') or [])[:20] if isinstance(n, str) and len(n) <= 253 and LAB.fullmatch(n)]
        if names:
            lines.append(f'{address} {" ".join(names)}')
    return BEGIN + ' (Range Control; do not edit)\n' + ''.join(line + '\n' for line in lines) + END + '\n'


def updated(current: str, managed: str) -> str:
    kept = re.sub(r'(?ms)^' + re.escape(BEGIN) + r'.*?^' + re.escape(END) + r'[^\n]*\n?', '', current)
    return kept.rstrip('\n') + '\n\n' + managed


def apply(path: Path, managed: str) -> bool:
    current = path.read_text()
    new = updated(current, managed)
    if new == current:
        return False
    fd, tmp = tempfile.mkstemp(prefix='.hosts-', dir=str(path.parent))
    with os.fdopen(fd, 'w') as stream:
        stream.write(new)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)
    return True


def fetch() -> list:
    url = (CREDENTIALS / 'range-control.url').read_text().strip().rstrip('/')
    if not url.startswith('https://'):
        raise ValueError('Range Control URL must be https')
    context = ssl.create_default_context(cafile=str(CREDENTIALS / 'ca.crt'))
    context.load_cert_chain(str(CREDENTIALS / 'client.crt'), str(CREDENTIALS / 'client.key'))
    request = urllib.request.Request(url + '/v1/range/directory', headers={'user-agent': 'xoc-livefire-hosts/1'})
    with urllib.request.urlopen(request, context=context, timeout=30) as response:
        return json.loads(response.read(1024 * 1024)).get('entries') or []


def main() -> int:
    try:
        entries = fetch()
    except (OSError, ValueError, ssl.SSLError) as error:
        print(json.dumps({'status': 'kept', 'reason': type(error).__name__}), flush=True)
        return 1
    changed = apply(HOSTS, block(entries))
    print(json.dumps({'status': 'updated' if changed else 'unchanged', 'entries': len(entries)}), flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
