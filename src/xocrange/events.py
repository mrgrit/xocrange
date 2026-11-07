"""Pure C1 adapters. Trusted scope comes from the collector context, never logs."""
from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from datetime import timezone

from .documents import MAX_BYTES, canonical, json_document, validate
from .errors import XocError
from .timestamps import parse_timestamp

VERSION = "xoc.event/0.2.0"
SOURCES = ("nftables", "suricata", "modsecurity", "osquery", "sysmon", "auditd", "apache-access", "apache-error")


def utc(value: str) -> str:
    try:
        # EVE uses +HHMM; Python 3.10 requires +HH:MM for fromisoformat.
        if not isinstance(value, str):
            raise ValueError("not a string")
        value = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", value)
        parsed = parse_timestamp(value)
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, TypeError, AttributeError, OverflowError) as exc:
        raise XocError("invalid_timestamp", "Timestamps require an explicit UTC offset.") from exc


@dataclass(frozen=True)
class Context:
    tenant_id: str
    range_id: str
    source_id: str
    evidence_ref: str
    observed_at: str

    def __post_init__(self):
        for value in (self.tenant_id, self.range_id, self.source_id):
            if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", value):
                raise XocError("invalid_context", "Scope identifiers must be bounded identifiers.")
        if not isinstance(self.evidence_ref, str) or not 1 <= len(self.evidence_ref) <= 512 or any(x in self.evidence_ref for x in "\r\n"):
            raise XocError("invalid_context", "A stable, non-secret evidence reference is required.")
        object.__setattr__(self, "observed_at", utc(self.observed_at))


def object_field(value, name):
    field = value.get(name)
    if not isinstance(field, dict):
        raise XocError("invalid_event", "A required source object is missing or invalid.")
    return field


def endpoint(address, port=None):
    try:
        if not isinstance(address, str):
            raise ValueError()
        result = {"ip": str(ipaddress.ip_address(address))}
        if port is not None:
            if isinstance(port, bool) or not isinstance(port, (str, int)):
                raise ValueError()
            number = int(port)
            if not 0 <= number <= 65535:
                raise ValueError()
            result["port"] = number
        return result
    except ValueError as exc:
        raise XocError("invalid_endpoint", "Source endpoint IP/port is invalid.") from exc


def make_event(raw, ctx, producer, *, discriminator, timestamp=None, category="network",
               kind="alert", action="alert", outcome="observed", severity=0):
    digest = hashlib.sha256(raw).hexdigest()
    identity = [VERSION, ctx.tenant_id, ctx.range_id, ctx.source_id, producer,
                ctx.evidence_ref, digest, discriminator]
    return {
        "schema_version": VERSION,
        "event_id": hashlib.sha256(canonical(identity)).hexdigest(),
        "tenant_id": ctx.tenant_id, "range_id": ctx.range_id, "source_id": ctx.source_id,
        "producer": producer, "timestamp": utc(timestamp) if timestamp is not None else ctx.observed_at,
        "observed_at": ctx.observed_at, "time_basis": "source" if timestamp is not None else "observed",
        "event": {"category": category, "type": kind, "action": action,
                  "outcome": outcome, "severity": severity},
        "evidence": {"ref": ctx.evidence_ref, "sha256": digest},
    }


def suricata(raw, ctx):
    data = json_document(raw)
    if not isinstance(data, dict) or data.get("event_type") != "alert":
        raise XocError("unsupported_event", "Only Suricata EVE alert records are supported in v0.1.")
    alert = object_field(data, "alert")
    level = alert.get("severity")
    if type(level) is not int or level not in (1, 2, 3):
        raise XocError("invalid_event", "Suricata severity must be 1, 2, or 3.")
    sid = alert.get("signature_id")
    if type(sid) is not int or sid < 0:
        raise XocError("invalid_event", "Suricata signature_id must be a nonnegative integer.")
    blocked = alert.get("action") == "blocked"
    event = make_event(raw, ctx, "suricata", discriminator="alert", timestamp=data.get("timestamp"),
                       action="rule-match", outcome="blocked" if blocked else "observed",
                       severity={1: 80, 2: 50, 3: 20}[level])
    event["rule"] = {"id": str(sid), "original_severity": str(level)}
    event["network"] = {"source": endpoint(data.get("src_ip"), data.get("src_port")),
                        "destination": endpoint(data.get("dest_ip"), data.get("dest_port"))}
    if "proto" in data:
        if not isinstance(data["proto"], str):
            raise XocError("invalid_event", "Protocol must be a string.")
        event["network"]["protocol"] = data["proto"].lower()
    return [event]


MODSEC_LEVELS = {"EMERGENCY": 100, "ALERT": 90, "CRITICAL": 80, "ERROR": 65,
                 "WARNING": 50, "NOTICE": 30, "INFO": 10, "DEBUG": 0}


def modsec_time(value):
    if value is None:
        return None
    if not isinstance(value, str):
        raise XocError("invalid_timestamp", "ModSecurity timestamp must be a string.")
    if re.match(r"\d{4}-", value):
        return utc(value)
    # ModSecurity 2.x JSON uses DD/Mon/YYYY:HH:MM:SS +/-HHMM.
    match = re.fullmatch(r"(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})", value)
    if not match:
        raise XocError("invalid_timestamp", "Unsupported ModSecurity timestamp format.")
    day, mon, year, hh, mm, ss, offset = match.groups()
    months = {m: n for n, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}
    if mon not in months:
        raise XocError("invalid_timestamp", "Unsupported month in ModSecurity timestamp.")
    return utc(f"{year}-{months[mon]:02d}-{day}T{hh}:{mm}:{ss}{offset[:3]}:{offset[3:]}")


def modsecurity(raw, ctx):
    data = json_document(raw)
    if not isinstance(data, dict):
        raise XocError("invalid_event", "ModSecurity record must be an object.")
    tx, audit = object_field(data, "transaction"), object_field(data, "audit_data")
    producers = audit.get("producer", [])
    if isinstance(producers, str):
        producers = [producers]
    if not isinstance(producers, list) or not all(isinstance(p, str) for p in producers) or not any(p.startswith("ModSecurity") for p in producers):
        raise XocError("invalid_event", "A ModSecurity producer marker is required.")
    txid = tx.get("transaction_id")
    messages = audit.get("messages", [])
    if not isinstance(txid, str) or not 1 <= len(txid) <= 128 or not isinstance(messages, list) or len(messages) > 256 or not all(isinstance(m, str) for m in messages):
        raise XocError("invalid_event", "Invalid transaction identifier or message array.")
    # Neither response.status=403 nor text in response.body establishes a WAF block.
    enforcing = audit.get("engine_mode") == "ENABLED"
    denied = [bool(re.match(r"^Access denied\b", m)) and enforcing for m in messages]
    timestamp = modsec_time(tx.get("time_stamp"))
    parent = make_event(raw, ctx, "modsecurity", discriminator="transaction", timestamp=timestamp,
                        category="web", kind="transaction", action="http-request",
                        outcome="blocked" if any(denied) else "observed",
                        severity=70 if any(denied) else 0)
    parent["correlation"] = {"transaction_id": txid}
    network = {}
    for side, ip_key, port_key in [("source", "remote_address", "remote_port"),
                                   ("destination", "local_address", "local_port")]:
        if ip_key in tx:
            network[side] = endpoint(tx[ip_key], tx.get(port_key))
    if network:
        parent["network"] = network
    result = [parent]
    for index, message in enumerate(messages):
        rule_id = re.search(r'\[id "([0-9]+)"\]', message)
        source_level = re.search(r'\[severity "([A-Z]+)"\]', message)
        level = source_level.group(1) if source_level else None
        child = make_event(raw, ctx, "modsecurity", discriminator=f"message:{index}", timestamp=timestamp,
                           category="web", action="rule-message", outcome="blocked" if denied[index] else "observed",
                           severity=MODSEC_LEVELS.get(level, 0))
        child["correlation"] = {"transaction_id": txid, "parent_event_id": parent["event_id"], "message_index": index}
        if rule_id:
            child["rule"] = {"id": rule_id.group(1)}
            if level:
                child["rule"]["original_severity"] = level
        if network:
            child["network"] = network.copy()
        result.append(child)
    return result


NFT_PREFIX = re.compile(
    r"^(?:(?P<iso>\d{4}-\d{2}-\d{2}T\S+) \S+ kernel: |"
    r"[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2} \S+ kernel: )?"
    r"(?:\[\s*\d+\.\d+\]\s*)?"
    r"\[(?:kt66|xoc)-(?:ips|fw)\] [^\r\n]*?\b(?P<action>DROP|ACCEPT|REJECT) "
    r"(?P<fields>IN=[^\r\n]*)$"
)


def nftables(raw, ctx):
    try:
        line = raw.decode("utf-8").rstrip("\r\n")
    except UnicodeError as exc:
        raise XocError("invalid_event", "nftables input must be UTF-8.") from exc
    match = NFT_PREFIX.fullmatch(line)
    if not match:
        raise XocError("unsupported_event", "Expected a trusted kt66/xoc firewall kernel log prefix.")
    fields = {}
    for key, value in re.findall(r"\b([A-Z]+)=(\S*)", match["fields"]):
        if key in fields:
            raise XocError("duplicate_key", "Duplicate field in firewall log.")
        fields[key] = value
    action = match["action"].lower()
    event = make_event(raw, ctx, "nftables", discriminator="packet", timestamp=match["iso"],
                       kind="access", action=action, outcome="allowed" if action == "accept" else "blocked",
                       severity=0 if action == "accept" else 50)
    event["network"] = {"source": endpoint(fields.get("SRC"), fields.get("SPT")),
                        "destination": endpoint(fields.get("DST"), fields.get("DPT"))}
    if "PROTO" in fields:
        event["network"]["protocol"] = fields["PROTO"].lower()
    return [event]


def normalize(source: str, raw: bytes, context: Context):
    if not raw or len(raw) > MAX_BYTES:
        raise XocError("input_size", "Expected a nonempty input of at most 1 MiB.")
    from .endpoint_events import osquery, sysmon, auditd, apache_access, apache_error
    adapters = {"suricata": suricata, "modsecurity": modsecurity, "nftables": nftables,
                "osquery": osquery, "sysmon": sysmon, "auditd": auditd,
                "apache-access": apache_access, "apache-error": apache_error}
    if source not in adapters:
        raise XocError("unknown_source", "Unknown source adapter.")
    try:
        events = adapters[source](raw, context)
    except (KeyError, TypeError, OverflowError, RecursionError) as exc:
        raise XocError("invalid_event", "Source record fields are missing or invalid.") from exc
    return [validate(event, "c1-event") for event in events]
