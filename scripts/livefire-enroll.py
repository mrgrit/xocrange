#!/usr/bin/env python3
"""Find a Live Fire Range Control on the classroom network and enroll this Core (ADR 0011).

  livefire-enroll.py run --out DIR --trust-dir /etc/xocrange/entitlements/trust \
      [--server HOST] [--code CODE] [--domain alice.lab] [--trust-key FILE] [--targets dvwa juice] [--interactive]

Exit codes: 0 enrolled (DIR holds license.json, identity.json, vendor.pem, credentials/,
enrollment.json), 3 no server or no code (install Core only), 4 enrollment refused or the
vendor key is not trusted, 2 usage. Standard library only; prints no secrets.

Discovery: UDP 47321 broadcast (or to --server), reply with the server URL and the CA that
signs its TLS certificate. Nothing is trusted from the reply alone: the class code goes over TLS
to that server, and the range license it returns must chain to a vendor key this Core already
trusts (or the --trust-key file), which `xoc license activate` checks again.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

PORT = 47321
SUFFIXES = ('lab', 'test', 'internal', 'home.arpa')
LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
RESERVED = {'www', 'siem', 'core', 'mail', 'dvwa', 'juice', 'juiceshop', 'xoc'}


class Stop(Exception):
    def __init__(self, code: int, message: str):
        self.code = code
        super().__init__(message)


def say(message: str) -> None:
    print(f'[Live Fire] {message}', file=sys.stderr, flush=True)


def broadcast_addresses() -> list[str]:
    addresses = ['255.255.255.255']
    try:
        for link in json.loads(subprocess.check_output(['ip', '-j', '-4', 'addr'], text=True)):
            for info in link.get('addr_info', []):
                if info.get('broadcast') and link.get('ifname') != 'lo' and not link.get('ifname', '').startswith(('docker', 'br-', 'veth')):
                    addresses.append(info['broadcast'])
    except (OSError, ValueError, subprocess.CalledProcessError):
        pass
    return list(dict.fromkeys(addresses))


def discover(server: str | None, wait: float = 2.0) -> list[dict]:
    nonce = secrets.token_hex(8)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(0.3)
    request = f'XOC-LIVEFIRE-DISCOVER/1 {nonce}'.encode()
    targets = [server] if server else broadcast_addresses()
    for target in targets:
        try:
            sock.sendto(request, (target, PORT))
        except OSError:
            continue
    found, deadline = {}, time.monotonic() + wait
    while time.monotonic() < deadline:
        try:
            data, _ = sock.recvfrom(8192)
        except socket.timeout:
            continue
        try:
            reply = json.loads(data)
        except ValueError:
            continue
        if (reply.get('service') == 'xoc-livefire' and reply.get('nonce') == nonce and str(reply.get('url', '')).startswith('https://')
                and '-----BEGIN CERTIFICATE-----' in str(reply.get('ca', ''))):
            found.setdefault(reply['url'], reply)
    return list(found.values())


def domain_ok(value: str) -> str:
    value = value.strip().lower().rstrip('.')
    labels = value.split('.')
    if len(value) > 253 or len(labels) < 2 or not all(LABEL.match(x) for x in labels):
        raise ValueError('도메인은 alice.lab 같은 영문 소문자 이름이어야 합니다.')
    if value in SUFFIXES or not any(value.endswith('.' + s) for s in SUFFIXES):
        raise ValueError('도메인은 .lab, .test, .internal, .home.arpa 중 하나로 끝나야 합니다.')
    if labels[0] in RESERVED:
        raise ValueError(f"'{labels[0]}'은 서비스 이름이라 도메인 첫 부분으로 쓸 수 없습니다.")
    return value


def call(server: dict, method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
    context = ssl.create_default_context(cadata=server['ca'])
    request = urllib.request.Request(server['url'].rstrip('/') + path, method=method,
                                     data=None if body is None else json.dumps(body).encode(),
                                     headers={'content-type': 'application/json'})
    try:
        with urllib.request.urlopen(request, context=context, timeout=30) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        try:
            detail = json.loads(error.read()).get('detail', '')
        except ValueError:
            detail = ''
        return error.code, {'detail': detail}
    except (urllib.error.URLError, ssl.SSLError, OSError) as error:
        raise Stop(4, f'Range Control에 연결하지 못했습니다: {error}')


def ask(prompt: str, interactive: bool) -> str:
    if not interactive:
        return ''
    try:
        with open('/dev/tty') as tty:
            sys.stderr.write(prompt); sys.stderr.flush()
            return tty.readline().strip()
    except OSError:
        return ''


def private(path: Path, data: bytes, mode: int = 0o600) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)


def run(a) -> dict:
    servers = discover(a.server)
    if not servers:
        raise Stop(3, 'Live Fire 서버를 찾을 수 없습니다. Core만 설치합니다.')
    server = servers[0]
    if len(servers) > 1:
        say('Live Fire 서버가 여러 개 응답했습니다: ' + ', '.join(s['url'] for s in servers) + f' → {server["url"]} 사용(다른 서버는 --livefire 주소)')
    say(f'Live Fire 서버를 찾았습니다: {server["url"]} (기관 {server.get("tenant_id")})')
    status, info = call(server, 'GET', '/enroll/info')
    if status != 200 or not info.get('issuer'):
        raise Stop(4, '이 Range Control은 아직 학생 등록을 받을 수 없습니다(공급사 발급자 인증서 없음). 관리자에게 문의하세요.')
    vendor = info['vendor_key']
    trusted = Path(a.trust_dir) / f'{vendor["key_id"]}.pem'
    known = trusted.read_text().strip() if trusted.exists() else (Path(a.trust_key).read_text().strip() if a.trust_key else None)
    if known != vendor['pem'].strip():
        raise Stop(4, f'공급사 키({vendor["key_id"]})를 확인할 수 없습니다. 이 Core가 신뢰하는 공급사 키가 아니면 등록하지 않습니다 '
                      '(공급사 공개키 파일을 --trust-vendor-key로 주거나, Core만 설치하려면 --no-livefire).')
    code = a.code or ask('  반 등록 코드 (강사에게 받은 코드, Enter=Core만 설치): ', a.interactive)
    if not code:
        raise Stop(3, '등록 코드가 없어 Core만 설치합니다.')
    domain, tries = a.domain, 0
    while True:
        tries += 1
        if not domain:
            domain = ask('  내 실습 도메인 (예: alice.lab — 끝은 .lab/.test/.internal/.home.arpa): ', a.interactive)
        try:
            domain = domain_ok(domain)
        except ValueError as error:
            if not a.interactive or tries >= 5:
                raise Stop(4, str(error))
            say(str(error)); domain = ''
            continue
        status, body = call(server, 'POST', '/enroll', {'code': code, 'domain': domain, 'targets': a.targets})
        if status == 201:
            break
        detail = body.get('detail') or f'HTTP {status}'
        if status == 409 and '도메인' in detail and a.interactive and tries < 5:
            say(detail); domain = ''
            continue
        if status == 403 and a.interactive and tries < 5:
            say(detail); code = ask('  반 등록 코드: ', True)
            if code:
                continue
        raise Stop(4, f'등록하지 못했습니다: {detail}')
    out = Path(a.out)
    (out / 'credentials').mkdir(mode=0o700, parents=True, exist_ok=True)
    private(out / 'license.json', json.dumps(body['license'], ensure_ascii=False).encode())
    private(out / 'identity.json', json.dumps(body['identity']).encode())
    private(out / 'vendor.pem', vendor['pem'].encode(), 0o644)
    for name, value in body['credentials'].items():
        private(out / 'credentials' / name, value.encode())
    summary = {'server': server['url'], 'tenant_id': server.get('tenant_id'), 'range_id': body['range_id'], 'domain': body['domain'],
               'address': body['address'], 'targets': body['targets'], 'vendor_key_id': vendor['key_id'],
               'institution_id': body['identity']['institution_id']}
    private(out / 'enrollment.json', json.dumps(summary, ensure_ascii=False, indent=1).encode(), 0o644)
    say(f'등록했습니다: {body["domain"]} (레인지 {body["range_id"]}, 주소 {body["address"]})')
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='command', required=True)
    r = sub.add_parser('run')
    r.add_argument('--out', required=True); r.add_argument('--trust-dir', required=True)
    r.add_argument('--server'); r.add_argument('--code'); r.add_argument('--domain'); r.add_argument('--trust-key')
    r.add_argument('--targets', nargs='*', default=[]); r.add_argument('--interactive', action='store_true')
    d = sub.add_parser('discover'); d.add_argument('--server')
    a = parser.parse_args()
    try:
        if a.command == 'discover':
            print(json.dumps([{k: v for k, v in s.items() if k != 'ca'} for s in discover(a.server)], ensure_ascii=False))
            return 0
        if a.server:
            try:
                ipaddress.ip_address(a.server)
            except ValueError:
                if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}', a.server):
                    raise Stop(2, 'invalid --livefire host')
        print(json.dumps(run(a), ensure_ascii=False))
        return 0
    except Stop as stop:
        say(str(stop))
        return stop.code


if __name__ == '__main__':
    sys.exit(main())
