"""The Wazuh C1 route must accept every C1 version the collector emits.

Events that Wazuh never matches stay unconfirmed, so the store reports a growing
backlog and installation acceptance fails. The engine check itself runs in a
disposable Wazuh container (see docs/development/ROADMAP-STATUS.md); this test
keeps the queue, rules and contract versions in step.
"""
import json
import re
from pathlib import Path
import xml.etree.ElementTree as ET

from xocrange.events import SOURCES


ROOT = Path(__file__).resolve().parents[1]


def rules():
    return ET.fromstring((ROOT / "components/siem/c1-rules.xml").read_text())


def test_queue_accepts_both_c1_versions():
    text = (ROOT / "components/siem/queue.py").read_text()
    for version in ("xoc.event/0.2.0", "xoc.event/0.3.0", "xoc.event/0.4.0"):
        assert repr(version) in text


def test_grouping_rule_uses_wazuh_regex_alternation():
    grouping = rules().find("rule[@id='110000']/field[@name='schema_version']").text
    # OS_Regex has no character classes; "[23]" silently matches nothing.
    assert "[" not in grouping
    assert set(grouping.split("|")) == {"^xoc.event/0.2.0$", "^xoc.event/0.3.0$", "^xoc.event/0.4.0$"}


def test_every_producer_has_a_confirming_rule():
    producers = {r.find("field[@name='producer']").text.strip("^$") for r in rules().iter("rule")
                 if r.find("field[@name='producer']") is not None}
    assert producers >= set(SOURCES) | {"xoc-agent", "xoc-facility"}
    for r in rules().iter("rule"):
        assert r.get("id").startswith("110")       # Store.confirm only accepts 110xxx
