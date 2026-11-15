"""ADR 0010: the host observer's lab network view uses fixed read-only commands and keeps only lab data."""
import json
from pathlib import Path

from xocrange import network_view as nv

PROJECT = 'xoc-core-security-path'
NETS = {'aaaaaaaaaaaa': ('ext', '10.20.30.0/24', '10.20.30.254', False),
        'bbbbbbbbbbbb': ('int', '10.20.40.0/24', '10.20.40.254', True),
        'cccccccccccc': ('user', '172.18.0.0/16', '172.18.0.1', False)}


class Engine:
    def __init__(self):
        self.calls = []

    def run(self, args, timeout=10):
        self.calls.append(args)
        if args[:2] == ['network', 'ls']:
            return '\n'.join(NETS) + '\n'
        if args[:2] == ['network', 'inspect']:
            return '\n'.join(json.dumps({'id': i + '0' * 52, 'segment': s, 'project': PROJECT, 'internal': internal,
                                         'ipam': [{'Subnet': sub, 'Gateway': gw}], 'options': {}})
                             for i, (s, sub, gw, internal) in NETS.items()) + '\n'
        if args[0] == 'ps':
            return '111111111111\n222222222222\n'
        if args[0] == 'inspect':
            return '\n'.join([
                json.dumps({'service': 'fw', 'project': PROJECT, 'pid': 4242, 'networks': {
                    'ext': {'NetworkID': 'aaaaaaaaaaaa' + '0' * 52, 'IPAddress': '10.20.30.1', 'IPPrefixLen': 24, 'MacAddress': 'ca:9a:40:c3:9e:dd'}}}),
                json.dumps({'service': 'web', 'project': PROJECT, 'pid': 4343, 'networks': {
                    'int': {'NetworkID': 'bbbbbbbbbbbb' + '0' * 52, 'IPAddress': '10.20.40.80', 'IPPrefixLen': 24, 'MacAddress': 'aa:bb:cc:dd:ee:01'},
                    'user': {'NetworkID': 'cccccccccccc' + '0' * 52, 'IPAddress': '172.18.0.9', 'IPPrefixLen': 16, 'MacAddress': 'aa:bb:cc:dd:ee:02'}}}),
            ]) + '\n'
        raise AssertionError(args)


def test_lab_segments_routes_and_mac_tables_only(tmp_path, monkeypatch):
    for name, state in (('br-aaaaaaaaaaaa', 'up'), ('br-bbbbbbbbbbbb', 'down')):
        stats = tmp_path / name / 'statistics'; stats.mkdir(parents=True)
        (tmp_path / name / 'operstate').write_text(state + '\n'); (tmp_path / name / 'mtu').write_text('1500\n')
        for k in ('rx_bytes', 'tx_bytes', 'rx_packets', 'tx_packets'):
            (stats / k).write_text('12\n')
    monkeypatch.setattr(nv, 'SYS', tmp_path)
    commands = []

    def fake_json(args):
        commands.append(args)
        if args[:3] == ['bridge', '-j', 'fdb']:
            return [{'mac': 'ca:9a:40:c3:9e:dd', 'ifname': 'veth1', 'master': args[-1], 'state': ''},
                    {'mac': '33:33:00:00:00:01', 'ifname': args[-1], 'flags': ['self'], 'state': 'permanent'}]
        if args[-2:] == ['addr', 'show']:
            return [{'ifname': 'eth0', 'address': 'ca:9a:40:c3:9e:dd', 'operstate': 'UP', 'addr_info': [{'family': 'inet', 'local': '10.20.30.1', 'prefixlen': 24}]}]
        if args[-2:] == ['route', 'show']:
            return [{'dst': '10.20.30.0/24', 'dev': 'eth0', 'prefsrc': '10.20.30.1'},
                    {'dst': '192.168.16.0/24', 'dev': 'eth9'},             # host LAN: dropped
                    {'dst': 'default', 'gateway': '10.20.30.254', 'dev': 'eth0'}]
        if args[-2:] == ['neigh', 'show']:
            return [{'dst': '10.20.30.20', 'lladdr': 'aa:aa:aa:aa:aa:aa', 'dev': 'eth0', 'state': ['STALE']},
                    {'dst': '172.18.0.1', 'lladdr': 'bb:bb:bb:bb:bb:bb', 'dev': 'eth1', 'state': ['REACHABLE']}]
        raise AssertionError(args)
    monkeypatch.setattr(nv, '_json', fake_json)
    engine = Engine()
    value = nv.observe_network(engine, PROJECT, 'plan-1')
    assert [s['id'] for s in value['segments']] == ['ext', 'int']                  # management network excluded
    ext, internal = value['segments']
    assert (ext['state'], ext['subnet'], ext['gateway'], ext['bridge']) == ('up', '10.20.30.0/24', '10.20.30.254', 'br-aaaaaaaaaaaa')
    assert ext['mac_table'] == [{'mac': 'ca:9a:40:c3:9e:dd', 'port': 'veth1', 'owner': 'fw'}]
    assert internal['internal'] and internal['state'] == 'down' and [e['service'] for e in internal['endpoints']] == ['web']
    fw = next(r for r in value['routers'] if r['service'] == 'fw')
    assert [r['dst'] for r in fw['routes']] == ['10.20.30.0/24', 'default']
    assert [n['ip'] for n in fw['neighbors']] == ['10.20.30.20']
    assert fw['interfaces'][0]['segment'] == 'ext'
    # Only fixed read-only commands ran.
    allowed = {('bridge', '-j', 'fdb', 'show', 'br'), ('nsenter', '-t')}
    assert all(tuple(c[:5]) in allowed or tuple(c[:2]) in allowed for c in commands)
    assert all(c[-1] == 'show' or c[:4] == ['bridge', '-j', 'fdb', 'show'] for c in commands)
    assert 'web' in {r['service'] for r in value['routers']} and 'ingress' not in {r['service'] for r in value['routers']}
    assert '172.18.0.9' not in json.dumps(value['segments'])
