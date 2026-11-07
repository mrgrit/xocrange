"""Local privileged collector transport; never listen on a network socket."""
import json
import socket
import sys

sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
sock.settimeout(5)
sock.connect('/var/ossec/queue/sockets/queue')
for line in sys.stdin.buffer:
    if len(line) > 60000 or not line.strip():
        raise SystemExit('Invalid C1 frame size')
    data = json.loads(line)
    if data.get('schema_version') != 'xoc.event/0.2.0':
        raise SystemExit('Unsupported C1 frame')
    sock.send(b'1:xoc-c1:' + line.rstrip(b'\n'))
    print(data['event_id'], flush=True)
