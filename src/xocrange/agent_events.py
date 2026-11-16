"""C1 v0.3 `xoc-agent`: tool receipts written by an entitled agent module (Joint Force).

The module appends one JSON object per tool call to its own activity volume
(`/run/xoc-activity/activity.jsonl`); the host collector reads it like any other log. Every
call is recorded whether the module's policy allowed or denied it. Receipts carry hashes of the
arguments and results, never their content. tenant_id/range_id come from the collector's
server-side identity, never from the record.
"""
import re

from .documents import json_document
from .errors import XocError
from .events import make_event

VERSION = "xoc.event/0.3.0"
ACTIVITY = "xoc.agent-activity/0.1.0"
ROLES = {"operator", "reviewer", "subagent", "red-team"}
NAME = re.compile(r"[a-z][a-z0-9_]{0,63}")
SKILL = re.compile(r"[a-z][a-z0-9-]{1,63}@\d+\.\d+\.\d+")
RECEIPT = re.compile(r"rcpt-[a-f0-9]{16}")
HASH = re.compile(r"[a-f0-9]{64}")
MODULE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}")


def _bad():
    raise XocError("invalid_event", "Agent activity fields are missing or invalid.")


def xoc_agent(raw, ctx):
    data = json_document(raw)
    if not isinstance(data, dict) or data.get("schema_version") != ACTIVITY:
        raise XocError("unsupported_event", "Agent activity records must be xoc.agent-activity/0.1.0.")
    role, tool, decision = data.get("role"), data.get("tool"), data.get("decision")
    if role not in ROLES or not isinstance(tool, str) or not NAME.fullmatch(tool) or decision not in ("allow", "deny"):
        _bad()
    agent = {"role": role, "tool": tool, "decision": decision}
    for key, pattern in (("code", NAME), ("skill", SKILL), ("receipt", RECEIPT), ("arguments_sha256", HASH),
                         ("result_sha256", HASH), ("module", MODULE)):
        value = data.get(key)
        if value is None:
            continue
        if not isinstance(value, str) or not pattern.fullmatch(value):
            _bad()
        agent[key] = value
    if data.get("mode") is not None:
        if data["mode"] not in ("live", "shadow"):
            _bad()
        agent["mode"] = data["mode"]
    event = make_event(raw, ctx, "xoc-agent", discriminator="receipt", timestamp=data.get("at"), category="agent",
                       kind="audit", action=tool, outcome="allowed" if decision == "allow" else "blocked",
                       severity=0 if decision == "allow" else 30, version=VERSION)
    event["agent"] = agent
    return [event]
