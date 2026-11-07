"""NFLOG metadata in the firewall namespace; never write packet payloads."""
import ctypes as C
from datetime import datetime, timezone
import ipaddress
from pathlib import Path
import socket
import struct

lib = C.CDLL('libnetfilter_log.so.1')
for name, restype, args in (
    ('nflog_open', C.c_void_p, []), ('nflog_bind_group', C.c_void_p, [C.c_void_p, C.c_uint16]),
    ('nflog_set_mode', C.c_int, [C.c_void_p, C.c_uint8, C.c_uint32]),
    ('nflog_set_qthresh', C.c_int, [C.c_void_p, C.c_uint32]),
    ('nflog_fd', C.c_int, [C.c_void_p]),
    ('nflog_get_payload', C.c_int, [C.c_void_p, C.POINTER(C.c_void_p)]),
    ('nflog_get_prefix', C.c_char_p, [C.c_void_p]),
    ('nflog_handle_packet', C.c_int, [C.c_void_p, C.c_char_p, C.c_int]),
):
    fn = getattr(lib, name); fn.restype = restype; fn.argtypes = args

handle = lib.nflog_open()
group = lib.nflog_bind_group(handle, 10) if handle else None
if not group or lib.nflog_set_mode(group, 2, 128) < 0 or lib.nflog_set_qthresh(group, 1) < 0:
    raise SystemExit('NFLOG group 10 initialization failed')
path = Path('/var/log/nftables/events.log')
path.parent.mkdir(exist_ok=True)


@C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_void_p, C.c_void_p, C.c_void_p)
def receive(group, message, data, opaque):
    payload = C.c_void_p()
    size = lib.nflog_get_payload(data, C.byref(payload))
    prefix = lib.nflog_get_prefix(data)
    if size < 20 or prefix not in (b'[xoc-fw] DROP ', b'[xoc-fw] ACCEPT '):
        return 0
    packet = C.string_at(payload, size)
    version = packet[0] >> 4
    if version == 4:
        offset, proto = (packet[0] & 15) * 4, packet[9]
        source, destination = packet[12:16], packet[16:20]
        fragmented = bool(struct.unpack('!H', packet[6:8])[0] & 0x1fff)
    elif version == 6 and size >= 40:
        offset, proto, source, destination, fragmented = 40, packet[6], packet[8:24], packet[24:40], False
    else:
        return 0
    protocol = {6: 'TCP', 17: 'UDP', 1: 'ICMP', 58: 'ICMPV6'}.get(proto, str(proto))
    fields = f'IN=netns OUT=netns SRC={ipaddress.ip_address(source)} DST={ipaddress.ip_address(destination)} PROTO={protocol}'
    if not fragmented and proto in (6, 17) and size >= offset + 4:
        sport, dport = struct.unpack('!HH', packet[offset:offset+4])
        fields += f' SPT={sport} DPT={dport}'
    stamp = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    # Rename rotation, leaving one previous generation for the collector.
    if path.exists() and path.stat().st_size > 8 * 1024 * 1024:
        path.replace(path.with_suffix('.log.1'))
    with path.open('a') as stream:
        stream.write(stamp + ' fw kernel: ' + prefix.decode() + fields + '\n')
    return 0


lib.nflog_callback_register.argtypes = [C.c_void_p, type(receive), C.c_void_p]
if lib.nflog_callback_register(group, receive, None) < 0:
    raise SystemExit('NFLOG callback registration failed')
reader = socket.fromfd(lib.nflog_fd(handle), socket.AF_NETLINK, socket.SOCK_RAW)
while True:
    packet = reader.recv(65536)
    if lib.nflog_handle_packet(handle, packet, len(packet)) < 0:
        raise SystemExit('NFLOG receive failed')
