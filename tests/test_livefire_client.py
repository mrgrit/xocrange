"""ADR 0011: the installer's enrollment client and the Core hosts sync (no network)."""
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


enroll = load('livefire_enroll', 'scripts/livefire-enroll.py')
hosts = load('livefire_hosts', 'scripts/livefire-hosts.py')


@pytest.mark.parametrize('value,ok', [('Alice.Lab', 'alice.lab'), ('team-7.test', 'team-7.test'), ('a.b.internal', 'a.b.internal'),
                                      ('x.home.arpa', 'x.home.arpa'), ('naver.com', None), ('lab', None), ('dvwa.lab', None),
                                      ('a_b.lab', None), ('xoc.range', None)])
def test_installer_checks_the_lab_domain_before_asking_the_server(value, ok):
    if ok:
        assert enroll.domain_ok(value) == ok
    else:
        with pytest.raises(ValueError):
            enroll.domain_ok(value)


def test_hosts_block_keeps_other_entries_and_only_writes_lab_names(tmp_path):
    entries = [{'address': '192.168.16.120', 'names': ['alice.lab', 'dvwa.alice.lab', 'juice.alice.lab']},
               {'address': '8.8.8.8', 'names': ['evil.lab']},                       # public address: dropped
               {'address': '192.168.16.121', 'names': ['www.naver.com', 'bob.lab']},   # real site name: dropped
               {'address': '127.0.0.1', 'names': ['loop.lab']},
               {'address': 'x', 'names': ['bad.lab']}, {'names': ['none.lab']}]
    managed = hosts.block(entries)
    assert managed.splitlines() == ['# BEGIN XOC LAB DOMAINS (Range Control; do not edit)',
                                    '192.168.16.120 alice.lab dvwa.alice.lab juice.alice.lab', '192.168.16.121 bob.lab',
                                    '# END XOC LAB DOMAINS']
    path = tmp_path / 'hosts'
    path.write_text('127.0.0.1 localhost\n192.168.16.100 core.example\n')
    assert hosts.apply(path, managed) is True
    assert hosts.apply(path, managed) is False                                       # unchanged
    replaced = hosts.block([{'address': '192.168.16.130', 'names': ['carol.lab']}])
    assert hosts.apply(path, replaced) is True
    text = path.read_text()
    assert text.startswith('127.0.0.1 localhost\n192.168.16.100 core.example\n')
    assert 'carol.lab' in text and 'alice.lab' not in text and text.count('# BEGIN XOC LAB DOMAINS') == 1
    assert path.stat().st_mode & 0o777 == 0o644
