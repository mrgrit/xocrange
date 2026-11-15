"""Read-only observation of the lab network for the datacenter view (ADR 0010).

Runs in the root host observer, never in a web process. Every command is fixed and read-only:
`docker network/container inspect` with reviewed format fields, `bridge -j fdb show br <bridge>`,
and `nsenter -t <pid> -n ip -j route|neigh|addr show` in the network namespace of the router-like
lab services. The result is bounded and holds only lab addressing (ext/pipe/dmz/int), MAC
addresses, interface state, packet counters and routes; no environment, mounts or host routes.
"""
from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import re
import subprocess

SEGMENTS = ('ext', 'pipe', 'dmz', 'int')
ROUTERS = ('ingress', 'fw', 'ips', 'web')
LIMIT = 64
MAC = re.compile(r'^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$')
IFNAME = re.compile(r'^[A-Za-z0-9_.@-]{1,32}$')
SYS = Path('/sys/class/net')


def _run(args: list[str], timeout: float = 5) -> str:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=True).stdout


def _json(args: list[str]):
    try:
        return json.loads(_run(args) or '[]')
    except (OSError, subprocess.SubprocessError, ValueError):
        return []


def _ip(value) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value))) if value else None
    except ValueError:
        return None


def _net(value) -> str | None:
    try:
        return str(ipaddress.ip_network(str(value), strict=False)) if value else None
    except ValueError:
        return None


def _mac(value) -> str | None:
    value = str(value or '').lower()
    return value if MAC.match(value) else None


def _counter(bridge: str, name: str) -> int | None:
    try:
        return int((SYS / bridge / 'statistics' / name).read_text())
    except (OSError, ValueError):
        return None


def _bridge(network: dict) -> str | None:
    name = (network.get('options') or {}).get('com.docker.network.bridge.name') or 'br-' + network['id'][:12]
    return name if re.fullmatch(r'br-[0-9a-f]{12}|[a-z][a-z0-9-]{0,14}', name) and (SYS / name).exists() else None


def observe_network(engine, project: str, plan_id: str) -> dict:
    result = {'schema_version': 'xoc.network/0.1.0', 'plan_id': plan_id,
              'observed_at': datetime.now(timezone.utc).isoformat(), 'segments': [], 'routers': []}
    ids = engine.run(['network', 'ls', '-q', '--filter', 'label=com.docker.compose.project=' + project], timeout=10).split()
    if len(ids) > 32 or any(not re.fullmatch('[0-9a-f]{12,64}', v) for v in ids):
        raise ValueError('Unexpected network inventory')
    fmt = ('{"id":{{json .Id}},"segment":{{json (index .Labels "com.docker.compose.network")}},'
           '"project":{{json (index .Labels "com.docker.compose.project")}},"internal":{{json .Internal}},'
           '"ipam":{{json .IPAM.Config}},"options":{{json .Options}}}')
    networks = {}
    for raw in (engine.run(['network', 'inspect', '--format', fmt, *ids], timeout=10).splitlines() if ids else []):
        row = json.loads(raw)
        if row.get('project') == project and row.get('segment') in SEGMENTS:
            networks[row['id']] = row
    containers = engine.run(['ps', '-q', '--filter', 'label=com.docker.compose.project=' + project], timeout=10).split()
    if len(containers) > 128 or any(not re.fullmatch('[0-9a-f]{12,64}', v) for v in containers):
        raise ValueError('Unexpected container inventory')
    cfmt = ('{"service":{{json (index .Config.Labels "com.docker.compose.service")}},'
            '"project":{{json (index .Config.Labels "com.docker.compose.project")}},"pid":{{json .State.Pid}},'
            '"networks":{{json .NetworkSettings.Networks}}}')
    endpoints, pids, mac_owner = {}, {}, {}
    for raw in (engine.run(['inspect', '--format', cfmt, *containers], timeout=10).splitlines() if containers else []):
        row = json.loads(raw)
        if row.get('project') != project or not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', str(row.get('service'))):
            continue
        if isinstance(row.get('pid'), int) and row['pid'] > 1:
            pids[row['service']] = row['pid']
        for attached in (row.get('networks') or {}).values():
            network = networks.get(attached.get('NetworkID'))
            if network is None:
                continue
            mac = _mac(attached.get('MacAddress'))
            item = {'service': row['service'], 'ip': _ip(attached.get('IPAddress')),
                    'prefix': attached.get('IPPrefixLen') if isinstance(attached.get('IPPrefixLen'), int) else None, 'mac': mac}
            endpoints.setdefault(network['segment'], []).append(item)
            if mac:
                mac_owner[mac] = (row['service'], network['segment'])
    for network in sorted(networks.values(), key=lambda n: SEGMENTS.index(n['segment'])):
        bridge = _bridge(network)
        ipam = (network.get('ipam') or [{}])[0] or {}
        segment = {'id': network['segment'], 'internal': bool(network.get('internal')),
                   'subnet': _net(ipam.get('Subnet')), 'gateway': _ip(ipam.get('Gateway')), 'bridge': bridge,
                   'endpoints': sorted(endpoints.get(network['segment'], []), key=lambda e: e['ip'] or '')[:LIMIT],
                   'state': 'unknown', 'mtu': None, 'counters': {}, 'mac_table': []}
        if bridge:
            try:
                segment['state'] = (SYS / bridge / 'operstate').read_text().strip()[:16]
                segment['mtu'] = int((SYS / bridge / 'mtu').read_text())
            except (OSError, ValueError):
                pass
            segment['counters'] = {k: _counter(bridge, k) for k in ('rx_bytes', 'tx_bytes', 'rx_packets', 'tx_packets')}
            table = []
            for entry in _json(['bridge', '-j', 'fdb', 'show', 'br', bridge]):
                mac = _mac(entry.get('mac'))
                if not mac or entry.get('state') == 'permanent' or 'self' in (entry.get('flags') or []):
                    continue
                owner = mac_owner.get(mac)
                table.append({'mac': mac, 'port': entry.get('ifname') if IFNAME.match(str(entry.get('ifname') or '')) else None,
                              'owner': owner[0] if owner and owner[1] == network['segment'] else None})
            segment['mac_table'] = table[:LIMIT]
        result['segments'].append(segment)
    lab = [ipaddress.ip_network(s['subnet']) for s in result['segments'] if s['subnet']]
    in_lab = lambda value: value == 'default' or (_net(value) is not None and any(ipaddress.ip_network(_net(value)).subnet_of(n) for n in lab))
    for service in ROUTERS:
        pid = pids.get(service)
        if not pid:
            continue
        base = ['nsenter', '-t', str(pid), '-n', 'ip', '-j']
        interfaces = []
        for link in _json(base + ['addr', 'show']):
            name = link.get('ifname')
            if not IFNAME.match(str(name or '')) or name == 'lo':
                continue
            mac = _mac(link.get('address'))
            addresses = [f"{_ip(a.get('local'))}/{a.get('prefixlen')}" for a in link.get('addr_info') or []
                         if a.get('family') == 'inet' and _ip(a.get('local'))]
            segment = next((s['id'] for s in result['segments'] for e in s['endpoints'] if e['service'] == service and e['mac'] == mac), None)
            interfaces.append({'name': name, 'mac': mac, 'addresses': addresses[:4], 'segment': segment,
                               'state': str(link.get('operstate') or '')[:16]})
        routes = [{'dst': str(r.get('dst'))[:43], 'via': _ip(r.get('gateway')), 'dev': r.get('dev') if IFNAME.match(str(r.get('dev') or '')) else None,
                   'src': _ip(r.get('prefsrc'))} for r in _json(base + ['route', 'show']) if in_lab(str(r.get('dst')))]
        neighbors = [{'ip': _ip(n.get('dst')), 'mac': _mac(n.get('lladdr')),
                      'dev': n.get('dev') if IFNAME.match(str(n.get('dev') or '')) else None,
                      'state': ','.join(str(s) for s in (n.get('state') or []))[:24],
                      'owner': (mac_owner.get(_mac(n.get('lladdr'))) or (None,))[0]}
                     for n in _json(base + ['neigh', 'show']) if _ip(n.get('dst')) and ':' not in str(n.get('dst')) and in_lab(str(n.get('dst')) + '/32')]
        result['routers'].append({'service': service, 'interfaces': interfaces[:8], 'routes': routes[:LIMIT],
                                  'neighbors': neighbors[:LIMIT]})
    return result
