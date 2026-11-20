"""C1 v0.4 `xoc-facility`: what happened in the facility simulator (Live Fire M4).

The module appends one JSON object per occurrence — an alarm raised or cleared, a fault
injected, cleared or expired, an operator action — to `events.jsonl` on its state volume
(`/run/xoc-facility`, ADR 0014). The host collector reads it like any other log. The record is
checked field by field; tenant_id/range_id come from the collector's server-side identity,
never from the record. Core only stores these events: the simulator and fault injection stay in
the module.
"""
import re

from .documents import json_document
from .errors import XocError
from .events import make_event

VERSION = "xoc.event/0.4.0"
RECORD = "xoc.facility-event/0.1.0"
# kind -> (event type, severity when the record carries no level)
KINDS = {"alarm": ("alert", 50), "info": ("observation", 10), "inject": ("audit", 30), "clear": ("audit", 20),
         "recover": ("observation", 20), "action": ("audit", 20)}
LEVELS = {"warning": 50, "critical": 80}
ALARM = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}")
ASSET = re.compile(r"[a-z][a-z0-9-]{0,63}")
FAULT = re.compile(r"[a-z][a-z0-9_]{0,47}")
TARGET = re.compile(r"\*|[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
UNSAFE = re.compile(r"[\x00-\x1f<>]")


def _bad():
    raise XocError("invalid_event", "Facility event fields are missing or invalid.")


def _text(value, limit):
    if not isinstance(value, str) or not value or len(value) > limit or UNSAFE.search(value):
        _bad()
    return value


def xoc_facility(raw, ctx):
    data = json_document(raw)
    if not isinstance(data, dict) or data.get("schema_version") != RECORD:
        raise XocError("unsupported_event", "Facility records must be xoc.facility-event/0.1.0.")
    kind = data.get("kind")
    if kind not in KINDS:
        _bad()
    facility = {"kind": kind, "message": _text(data.get("message"), 240)}
    if data.get("level") is not None:
        if data["level"] not in LEVELS:
            _bad()
        facility["level"] = data["level"]
    for key, pattern in (("alarm", ALARM), ("asset_id", ASSET), ("fault", FAULT), ("target", TARGET)):
        value = data.get(key)
        if value is None:
            continue
        if not isinstance(value, str) or not pattern.fullmatch(value):
            _bad()
        facility[key] = value
    if data.get("requested_by") is not None:
        facility["requested_by"] = _text(data["requested_by"], 150)
    event_type, severity = KINDS[kind]
    if kind == "alarm":
        severity = LEVELS.get(facility.get("level"), severity)
    discriminator = ":".join((kind, facility.get("alarm") or facility.get("fault") or "", facility.get("target") or ""))
    event = make_event(raw, ctx, "xoc-facility", discriminator=discriminator, timestamp=data.get("at"), category="facility",
                       kind=event_type, action=kind, outcome="observed", severity=severity, version=VERSION)
    event["facility"] = facility
    return [event]
