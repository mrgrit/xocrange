"""Bounded endpoint/Apache adapters. No command lines, headers or request bodies."""
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import re
import xml.etree.ElementTree as ET

from .documents import json_document
from .errors import XocError
from .events import endpoint, make_event, modsec_time, object_field


def fail():
    raise XocError("invalid_event", "Required source fields are missing, ambiguous or invalid.")


def text(value, limit=1024):
    if not isinstance(value, str) or not 1 <= len(value) <= limit or any(ord(c) < 32 for c in value):
        fail()
    return value


def number(value, maximum=2**63-1):
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]+", str(value)):
        fail()
    result = int(value)
    if result > maximum:
        fail()
    return result


def epoch(value):
    try:
        stamp = Decimal(str(value))
        if not stamp.is_finite() or stamp < 0:
            fail()
        return datetime.fromtimestamp(float(stamp), timezone.utc).isoformat().replace("+00:00", "Z")
    except (InvalidOperation, ValueError, OverflowError, OSError):
        fail()


def process_fields(data, mapping):
    result = {}
    for origin, target in mapping.items():
        if data.get(origin) not in (None, "", "-"):
            result[target] = number(data[origin]) if target in ("pid", "parent_pid") else text(data[origin])
    return result


def osquery(raw, ctx):
    data = json_document(raw)
    if not isinstance(data, dict):
        fail()
    name = text(data.get("name"), 128)
    timestamp = epoch(data["unixTime"])
    rows = []
    if "snapshot" in data:
        if not isinstance(data["snapshot"], list):
            fail()
        rows = [("snapshot", row) for row in data["snapshot"]]
    elif "diffResults" in data:
        diff = object_field(data, "diffResults")
        for action in ("added", "removed"):
            if not isinstance(diff.get(action, []), list):
                fail()
            rows += [(action, row) for row in diff.get(action, [])]
    else:
        if data.get("action") not in ("added", "removed"):
            fail()
        rows = [(data["action"], object_field(data, "columns"))]
    if len(rows) > 256 or not all(isinstance(row, dict) for _, row in rows):
        fail()
    # A zero-row snapshot is still an observed query result.
    count = len(rows)
    result = []
    for index, (action, row) in enumerate(rows or [("snapshot", {})]):
        event = make_event(raw, ctx, "osquery", discriminator=f"row:{index}", timestamp=timestamp,
                           category="host", kind="observation", action=action)
        event["osquery"] = {"query": name, "row_index": index, "row_count": count}
        proc = process_fields(row, {"pid": "pid", "parent": "parent_pid", "path": "executable", "name": "name"})
        if proc:
            event["process"] = proc
        if "uid" in row:
            event["user"] = {"id": str(number(row["uid"]))}
        if "hostIdentifier" in data:
            event["host"] = {"name": text(data["hostIdentifier"], 255)}
        # Explicit metadata allowlist: osquery can otherwise select arbitrary secrets.
        allowed = ("pid", "parent", "uid", "gid", "name", "path", "version", "port", "address", "protocol", "family", "state", "sha256")
        columns = {key: text(str(value)) for key, value in row.items() if key in allowed and value not in (None, "")}
        if columns:
            event["osquery"]["columns"] = columns
        result.append(event)
    return result


def sysmon(raw, ctx):
    try:
        payload = raw.decode("utf-8").strip()
        banners = ('Sysmon v', 'Sysinternals - ', 'By Mark Russinovich,', 'Copyright (C)',
                   'Licensed under ', 'Using pugixml.', 'Loading configuration file with schema version ',
                   'Sysmon schema version: ', 'Configuration file validated.',
                   'Stopping....', 'Total events: ', 'Lost events: ')
        # The sensor's own start failure (eBPF ring buffer, ENOMEM) is a
        # telemetry gap to report, not unparseable input to quarantine.
        failures = ('libbpf: ', 'Telemetry failed to start')
        if len(payload) < 512 and payload.startswith(failures) and '<' not in payload:
            return [make_event(raw, ctx, 'sysmon', discriminator='diagnostic', category='host',
                               kind='diagnostic', action='agent-failure', severity=65)]
        if len(payload) < 512 and payload.startswith(banners) and '<' not in payload:
            lost = re.fullmatch(r'Lost events: (\d+), in \d+ notifications', payload)
            return [make_event(raw, ctx, 'sysmon', discriminator='diagnostic', category='host',
                               kind='diagnostic', action='agent-loss' if lost and int(lost[1]) else 'agent-status',
                               severity=65 if lost and int(lost[1]) else 0)]
        if "<!" in payload:
            fail()  # No DTD, entities or comments; never resolve external content.
        start = payload.find("<Event")
        if start < 0 or (start and not re.fullmatch(r"[^\r\n<>]*\bsysmon(?:\[\d+\])?:\s*", payload[:start], re.I)):
            fail()
        tree = ET.fromstring(payload[start:])
        for element in tree.iter():
            element.tag = element.tag.split("}")[-1]
        if tree.tag != "Event":
            fail()
        system = tree.find("System")
        if system is None or system.find("Provider") is None or system.find("Provider").get("Name") != "Linux-Sysmon":
            # Windows exported XML has the same data contract, but a different provider.
            if system is None or system.find("Provider") is None or system.find("Provider").get("Name") != "Microsoft-Windows-Sysmon":
                fail()
        event_id = number(system.findtext("EventID"), 65535)
        fields = {}
        for field in tree.findall("EventData/Data"):
            key = field.get("Name")
            if not key or key in fields:
                fail()
            fields[key] = field.text or ""
        clock = system.find("TimeCreated")
        timestamp = clock.get("SystemTime") if clock is not None else None
        if timestamp is None and fields.get("UtcTime"):
            timestamp = fields["UtcTime"].replace(" ", "T") + "Z"
        categories = {1: ("process", "start"), 3: ("network", "connect"), 5: ("process", "stop"),
                      11: ("file", "create"), 23: ("file", "delete"), 26: ("file", "delete")}
        category, action = categories.get(event_id, ("host", "sysmon-event"))
        event = make_event(raw, ctx, "sysmon", discriminator="event", timestamp=timestamp,
                           category=category, kind="observation", action=action)
        event["sysmon"] = {"event_id": event_id}
        proc = process_fields(fields, {"ProcessId": "pid", "ParentProcessId": "parent_pid", "Image": "executable", "ProcessGuid": "entity_id"})
        if proc:
            event["process"] = proc
        if system.findtext("Computer"):
            event["host"] = {"name": text(system.findtext("Computer"), 255)}
        if fields.get("User"):
            event["user"] = {"id": text(fields["User"], 256)}
        if fields.get("TargetFilename"):
            event["file"] = {"path": text(fields["TargetFilename"])}
        network = {}
        for prefix, side in (("Source", "source"), ("Destination", "destination")):
            if fields.get(prefix + "Ip"):
                network[side] = endpoint(fields[prefix + "Ip"], fields.get(prefix + "Port"))
        if network:
            if fields.get("Protocol"):
                network["protocol"] = fields["Protocol"].lower()
            event["network"] = network
        return [event]
    except (UnicodeError, ET.ParseError, AttributeError, TypeError):
        fail()


AUDIT_HEADER = re.compile(r"^(?:node=(\S+) )?type=([A-Z0-9_]+) msg=audit\(([0-9]+(?:\.[0-9]+)?):(\d+)\):\s*(.*)$")
AUDIT_FIELD = re.compile(r'(?<!\S)([A-Za-z0-9_]+)=("[^"\r\n]*"|[^\s]+)')


def auditd(raw, ctx):
    try:
        # ENRICHED audit records use ASCII GS (0x1d), which str.splitlines treats
        # as a newline. It separates interpreted fields, not audit records.
        lines = raw.decode("utf-8").strip().split('\n')
    except UnicodeError:
        fail()
    identity, types, syscall = None, [], {}
    for line in lines:
        match = AUDIT_HEADER.fullmatch(line)
        if not match:
            fail()
        node, kind, timestamp, serial, tail = match.groups()
        current = (node, timestamp, serial)
        if identity is not None and identity != current:
            raise XocError("mixed_audit_event", "Audit records must share node, timestamp and serial.")
        identity = current
        if kind not in types:
            types.append(kind)
        if kind == "SYSCALL":
            if syscall:
                fail()
            for key, value in AUDIT_FIELD.findall(tail):
                if key in syscall:
                    fail()
                # Decode only explicitly needed values; never export EXECVE args/PROCTITLE.
                if value.startswith('"'):
                    value = value[1:-1]
                elif key in ("exe", "comm", "key") and re.fullmatch(r"(?:[0-9A-Fa-f]{2})+", value):
                    try:
                        value = bytes.fromhex(value).decode("utf-8")
                    except UnicodeError:
                        fail()
                syscall[key] = value
    if not identity or len(types) > 64:
        fail()
    success = syscall.get("success")
    # Failed syscalls are not proof of a security control blocking a request.
    event = make_event(raw, ctx, "auditd", discriminator="audit-event", timestamp=epoch(identity[1]),
                       category="host", kind="audit", action="syscall" if syscall else "audit-record",
                       outcome={"yes": "success", "no": "failure"}.get(success, "observed"))
    event["audit"] = {"serial": identity[2], "record_types": types, "complete": "EOE" in types}
    for key in ("arch", "syscall", "key"):
        if syscall.get(key) not in (None, "(null)"):
            event["audit"][key] = text(syscall[key], 128)
    proc = process_fields(syscall, {"pid": "pid", "ppid": "parent_pid", "exe": "executable", "comm": "name"})
    if proc:
        event["process"] = proc
    if "uid" in syscall:
        event["user"] = {"id": str(number(syscall["uid"]))}
    if identity[0]:
        event["host"] = {"name": text(identity[0], 255)}
    return [event]


ACCESS = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "((?:[^"\\\r\n]|\\.)*)" (\d{3}) (\d+|-)(?: "(?:[^"\\\r\n]|\\.)*" "(?:[^"\\\r\n]|\\.)*")?(?: xoc_id=([A-Za-z0-9_@.-]+))?$')


def apache_access(raw, ctx):
    try:
        value = raw.decode("utf-8").strip()
        if value.startswith("{"):
            data = json_document(raw)
            if not isinstance(data, dict):
                fail()
            address, status = data.get("client_ip"), number(data.get("status"), 599)
            timestamp = data.get("timestamp")
            method, count, request_id = data.get("method"), data.get("bytes"), data.get("request_id")
        else:
            match = ACCESS.fullmatch(value)
            if not match:
                fail()
            address, timestamp, request, status, count, request_id = match.groups()
            method = request.split(' ',1)[0] if request != '-' else None
            if method is not None and not re.fullmatch('[A-Z]+',method):fail()
            timestamp, status = modsec_time(timestamp), int(status)
        if status < 100:
            fail()
        event = make_event(raw, ctx, "apache-access", discriminator="request", timestamp=timestamp,
                           category="web", kind="access", action="http-request",
                           outcome="failure" if status >= 400 else "success")
        event["network"] = {"source": endpoint(address)}
        event["http"] = {"status_code": status}
        if method and method != '-':
            event["http"]["method"] = text(method, 32)
        if count not in (None, "-"):
            event["http"]["bytes"] = number(count)
        if request_id and request_id != "-":
            event["correlation"] = {"transaction_id": text(request_id, 128)}
        return [event]
    except UnicodeError:
        fail()


ERROR = re.compile(r"^\[([^\]]+)\] \[([a-zA-Z0-9_]+):([a-z]+)\] \[pid (\d+)(?::tid [^\]]+)?\](?: \[client ([^\]]+)\])? (.*)$")
LEVELS = {"emerg": 100, "alert": 90, "crit": 80, "error": 65, "warn": 50, "notice": 30, "info": 10, "debug": 0}


def apache_error(raw, ctx):
    try:
        match = ERROR.fullmatch(raw.decode("utf-8").strip())
        if not match:
            fail()
        clock, module, level, pid, client, message = match.groups()
        if level not in LEVELS:
            fail()
        # Legacy Apache timestamps have no offset. Do not invent a timezone.
        timestamp = clock if re.match(r"\d{4}-\d{2}-\d{2}T", clock) else None
        event = make_event(raw, ctx, "apache-error", discriminator="error", timestamp=timestamp,
                           category="web", kind="diagnostic", action="server-message", severity=LEVELS[level])
        event["log"] = {"level": level, "module": module}
        code = re.match(r"(AH\d{5}):", message)
        if code:
            event["log"]["code"] = code[1]
        event["process"] = {"pid": number(pid)}
        if client:
            host, port = client.rsplit(":", 1)
            event["network"] = {"source": endpoint(host.strip("[]"), port)}
        return [event]
    except (UnicodeError, ValueError):
        fail()
