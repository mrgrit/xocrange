"""Validated local raw-source transport. Socket delivery is not analysis success."""
import json
import re
import socket
import sys

sources = {'nftables','suricata','modsecurity','osquery','sysmon','auditd','apache-access','apache-error'}
sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
sock.settimeout(5)
sock.connect('/var/ossec/queue/sockets/queue')
for line in sys.stdin.buffer:
    if len(line) > 400000: raise SystemExit('Native transport envelope is too large')
    value = json.loads(line)
    if set(value) != {'id','source','payload'} or value['source'] not in sources or not re.fullmatch('[a-f0-9]{64}', value['id']):
        raise SystemExit('Invalid native transport identity')
    payload = value['payload']
    if not isinstance(payload,str) or not payload or any(c in payload for c in '\r\n\0') or len(payload.encode()) > 60000:
        raise SystemExit('Invalid native transport frame')
    location = 'xoc-native/' + value['id'] + '/' + value['source']
    sock.send(('1:' + location + ':' + payload).encode())
    print(value['id'], flush=True)
