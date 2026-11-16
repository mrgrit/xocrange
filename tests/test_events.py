from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

from xocrange.documents import json_document, validate
from xocrange.errors import XocError
from xocrange.events import Context, normalize

FIXTURES = Path(__file__).parent / "fixtures/events"


@pytest.fixture
def context():
    return Context("community", "range-01", "sensor-01", "fixture://capture/record-001", "2026-11-07T03:35:00Z")


def payload(name):
    return (FIXTURES / name).read_bytes()


def encode(value):
    return json.dumps(value).encode()


def test_suricata_evidence_time_and_scope(context):
    raw = payload("suricata-alert.json")
    event, = normalize("suricata", raw, context)
    assert event["timestamp"] == "2026-11-07T03:34:56.123456Z"
    assert event["time_basis"] == "source"
    assert event["event"]["outcome"] == "blocked"
    assert event["event"]["severity"] == 50
    assert event["network"]["destination"]["port"] == 443
    assert event["evidence"]["sha256"] == hashlib.sha256(raw).hexdigest()
    spoofed = json.loads(raw) | {"tenant_id": "attacker", "range_id": "other", "source_id": "other"}
    converted, = normalize("suricata", encode(spoofed), context)
    assert (converted["tenant_id"], converted["range_id"], converted["source_id"]) == ("community", "range-01", "sensor-01")


def test_identity_is_replay_stable_but_scope_and_record_sensitive(context):
    raw = payload("suricata-alert.json")
    initial = normalize("suricata", raw, context)[0]["event_id"]
    later = replace(context, observed_at="2026-11-08T00:00:00Z")
    assert normalize("suricata", raw, later)[0]["event_id"] == initial
    for changed in (replace(context, tenant_id="other"), replace(context, range_id="other"),
                    replace(context, source_id="other"), replace(context, evidence_ref="fixture://capture/record-002")):
        assert normalize("suricata", raw, changed)[0]["event_id"] != initial
    assert normalize("suricata", raw + b"\n", context)[0]["event_id"] != initial


def test_detection_is_not_a_claim_that_traffic_was_allowed(context):
    data = json.loads(payload("suricata-alert.json"))
    data["alert"]["action"] = "allowed"
    assert normalize("suricata", encode(data), context)[0]["event"]["outcome"] == "observed"


def test_modsecurity_transaction_children_and_no_sensitive_body(context):
    events = normalize("modsecurity", payload("modsecurity-audit.json"), context)
    parent, warning, block = events
    assert parent["timestamp"] == "2026-11-07T03:34:56Z"
    assert parent["event"]["outcome"] == block["event"]["outcome"] == "blocked"
    assert warning["event"]["outcome"] == "observed"
    assert warning["rule"]["id"] == "941100"
    assert len({e["event_id"] for e in events}) == 3
    for index, child in enumerate(events[1:]):
        assert child["correlation"]["parent_event_id"] == parent["event_id"]
        assert child["correlation"]["message_index"] == index
    assert "SYNTHETIC-DO-NOT-EXPORT" not in json.dumps(events)
    assert "Synthetic body" not in json.dumps(events)


def test_http_403_and_body_markers_do_not_invent_waf_events(context):
    data = json.loads(payload("modsecurity-audit.json"))
    data["audit_data"]["messages"] = []
    data["response"]["body"] = 'Access denied [id "123"] [severity "CRITICAL"]'
    result = normalize("modsecurity", encode(data), context)
    assert len(result) == 1
    assert result[0]["event"]["outcome"] == "observed"
    assert "rule" not in result[0]


@pytest.mark.parametrize("mode", ["DETECTION_ONLY", "DISABLED", None])
def test_non_enforcing_modsecurity_never_claims_block(context, mode):
    data = json.loads(payload("modsecurity-audit.json"))
    data["audit_data"]["engine_mode"] = mode
    assert all(event["event"]["outcome"] == "observed" for event in normalize("modsecurity", encode(data), context))


def test_modsecurity_requires_producer_provenance(context):
    data = json.loads(payload("modsecurity-audit.json"))
    data["audit_data"]["producer"] = ["Other server"]
    with pytest.raises(XocError, match="producer"):
        normalize("modsecurity", encode(data), context)


def test_nftables_source_time_fallback_and_prefix(context):
    raw = payload("nftables-drop.log")
    event, = normalize("nftables", raw, context)
    assert event["timestamp"] == "2026-11-07T03:34:56Z"
    assert event["event"]["action"] == "drop"
    assert event["network"]["source"]["ip"] == "192.0.2.10"
    kernel = raw[raw.index(b"[kt66-ips]"):]
    missing_time, = normalize("nftables", kernel, context)
    assert missing_time["time_basis"] == "observed"
    assert missing_time["timestamp"] == context.observed_at
    accepted, = normalize("nftables", kernel.replace(b"DROP", b"ACCEPT"), context)
    assert accepted["event"]["outcome"] == "allowed"
    with pytest.raises(XocError):
        normalize("nftables", b"HTTP body " + kernel, context)
    with pytest.raises(XocError):
        normalize("nftables", kernel.rstrip() + b" SRC=203.0.113.1", context)


@pytest.mark.parametrize("field,value", [("timestamp", ""), ("timestamp", "2026-11-07T12:34:56"),
                                       ("timestamp", "2026-11-07T12:34:56+09:99"),
                                       ("timestamp", "0001-01-01T00:00:00+01:00"),
                                       ("src_ip", "999.1.1.1"), ("src_port", 65536),
                                       ("src_port", True), ("src_port", 1.5), ("proto", "TCP\nSECRET")])
def test_invalid_source_fields_fail_closed(context, field, value):
    data = json.loads(payload("suricata-alert.json"))
    data[field] = value
    with pytest.raises(XocError):
        normalize("suricata", encode(data), context)


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1e999}', b'\xff', b'[]' * 600000])
def test_invalid_or_unbounded_json_is_rejected(raw):
    with pytest.raises(XocError):
        json_document(raw)


def test_contract_rejects_unapproved_raw_fields_and_invalid_utc(context):
    event = normalize("suricata", payload("suricata-alert.json"), context)[0]
    with pytest.raises(XocError):
        validate(event | {"raw": "secret"}, "c1-event")
    with pytest.raises(XocError):
        validate(event | {"timestamp": "2026-99-99T00:00:00Z"}, "c1-event")
    with pytest.raises(XocError):
        validate(event | {"network": {"source": {"ip": "999.1.1.1"}}}, "c1-event")
    with pytest.raises(XocError):
        replace(context, observed_at="2026-11-07")


def test_missing_source_time_is_explicit(context):
    data = json.loads(payload("suricata-alert.json"))
    del data["timestamp"]
    event, = normalize("suricata", encode(data), context)
    assert event["timestamp"] == event["observed_at"]
    assert event["time_basis"] == "observed"


AGENT = {"schema_version": "xoc.agent-activity/0.1.0", "at": "2026-11-16T12:18:20Z", "role": "operator",
         "tool": "siem_search", "decision": "allow", "mode": "live", "code": "ok", "skill": "ip-risk-triage@0.1.0",
         "receipt": "rcpt-0123456789abcdef", "arguments_sha256": "a" * 64, "result_sha256": "b" * 64, "module": "m7-operator"}


def test_agent_activity_is_c1_v03_and_keeps_only_hashes(context):
    import json
    event, = normalize("xoc-agent", json.dumps(AGENT).encode(), context)
    assert event["schema_version"] == "xoc.event/0.3.0" and event["producer"] == "xoc-agent"
    assert event["event"] == {"category": "agent", "type": "audit", "action": "siem_search", "outcome": "allowed", "severity": 0}
    assert event["agent"]["receipt"] == "rcpt-0123456789abcdef" and event["tenant_id"] == "community"
    denied, = normalize("xoc-agent", json.dumps(AGENT | {"tool": "shell", "decision": "deny", "code": "floor"}).encode(), context)
    assert denied["event"]["outcome"] == "blocked" and denied["agent"]["code"] == "floor"
    forged, = normalize("xoc-agent", json.dumps(AGENT | {"tenant_id": "other", "range_id": "other"}).encode(), context)
    assert forged["tenant_id"] == "community" and forged["range_id"] == "range-01"     # identity is server-side
    v2, = normalize("suricata", (FIXTURES / "suricata-alert.json").read_bytes(), context) if (FIXTURES / "suricata-alert.json").exists() else (None,)
    if v2:
        assert v2["schema_version"] == "xoc.event/0.2.0"                               # existing producers stay v0.2


@pytest.mark.parametrize("change", [{"schema_version": "x"}, {"role": "admin"}, {"tool": "Shell; rm"}, {"decision": "maybe"},
                                    {"receipt": "nope"}, {"skill": "x"}, {"mode": "auto"}, {"arguments_sha256": "zz"}])
def test_agent_activity_fails_closed(context, change):
    import json
    with pytest.raises(XocError):
        normalize("xoc-agent", json.dumps(AGENT | change).encode(), context)
