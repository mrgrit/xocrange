import sys

import pytest

from xocrange.collector import Collector, Transport
from xocrange.errors import XocError
from xocrange.event_store import Store

# Stands in for the queue scripts: one acknowledgment line per input line.
ECHO = [sys.executable, '-I', '-c', '''
import sys
for line in sys.stdin.buffer:
    value = line.strip()
    if value == b'die':
        raise SystemExit(3)
    if value == b'wrong':
        value = b'other'
    if value == b'hang':
        import time; time.sleep(60)
    sys.stdout.buffer.write(value + b'\\n'); sys.stdout.flush()
''']


def frames(ids):
    return b''.join(value.encode() + b'\n' for value in ids)


def test_one_process_serves_every_batch_without_pipe_deadlock():
    transport = Transport(ECHO)
    try:
        assert transport.send(frames(['a', 'b']), ['a', 'b']) == ['a', 'b']
        first = transport.process.pid
        # Far more acknowledgments than a pipe buffer holds while still writing.
        ids = [f'{n:064x}' for n in range(5000)]
        assert transport.send(frames(ids), ids) == ids
        assert transport.process.pid == first
        assert transport.send(b'', []) == []
    finally:
        transport.close()
    assert transport.process is None


def test_failure_keeps_acknowledged_prefix_and_restarts_next_batch():
    transport = Transport(ECHO)
    try:
        with pytest.raises(XocError) as raised:
            transport.send(frames(['a', 'b', 'die', 'c']), ['a', 'b', 'die', 'c'])
        assert raised.value.code == 'collection_command' and raised.value.acked == ['a', 'b']
        assert transport.process is None
        assert transport.send(frames(['c']), ['c']) == ['c']
        with pytest.raises(XocError) as raised:
            transport.send(frames(['d', 'wrong']), ['d', 'wrong'])
        assert raised.value.code == 'transport_ack' and raised.value.acked == ['d']
        with pytest.raises(XocError) as raised:
            transport.send(frames(['e', 'hang']), ['e', 'hang'], timeout=1)
        assert raised.value.code == 'collection_command' and raised.value.acked == ['e']
        assert transport.process is None
    finally:
        transport.close()


def test_unstartable_transport_is_a_collection_error():
    transport = Transport(['/nonexistent/xoc-transport'])
    with pytest.raises(XocError) as raised:
        transport.send(b'a\n', ['a'])
    assert raised.value.code == 'collection_command' and raised.value.acked == []


def test_collector_marks_only_acknowledged_events_sent(tmp_path):
    collector = Collector.__new__(Collector)
    collector.store = Store(tmp_path / 'store')
    collector.engine = type('Engine', (), {'compose': []})()
    collector.transports = {'xoc-queue.py': Transport(ECHO)}
    with collector.store.db:
        for value in ('a', 'b', 'die'):
            collector.store.db.execute('INSERT INTO records (ref,source,observed,sha256,raw) VALUES (?,?,?,?,?)',
                                       (value, 'sysmon', 'now', value, b''))
            collector.store.db.execute('INSERT INTO events (id,ref,producer,observed,event) VALUES (?,?,?,?,?)',
                                       (value, value, 'sysmon', 'now', '{}'))
    try:
        with pytest.raises(XocError) as raised:
            collector.deliver('xoc-queue.py', 'events', frames(['a', 'b', 'die']), ['a', 'b', 'die'], 'siem_transport')
        assert raised.value.code == 'collection_command'
        sent = dict(collector.store.db.execute('SELECT id, sent FROM events'))
        assert sent['a'] and sent['b'] and sent['die'] is None
        with pytest.raises(XocError) as raised:
            collector.deliver('xoc-queue.py', 'events', frames(['wrong']), ['wrong'], 'siem_transport')
        assert raised.value.code == 'siem_transport'
    finally:
        collector.close()
