import copy
import json
from pathlib import Path
import runpy
import shutil

import pytest
import yaml

from xocrange.documents import yaml_document
from xocrange.errors import XocError
from xocrange.network_policy import check_addresses
from xocrange.planner import plan

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def security_checkout(checkout):
    for relative in ("components/security-path", "tests/fixtures/modules/security-probe"):
        shutil.copytree(ROOT / relative, checkout / relative)
    return checkout


def security_plan(root, probe=False, **kwargs):
    return plan(root, preset="security-path", allow_experimental=True, allow_fixtures=probe,
                include=["fixture-security-probe"] if probe else [], **kwargs)


def test_experimental_path_requires_explicit_opt_in(security_checkout):
    with pytest.raises(XocError) as error:
        plan(security_checkout, preset="security-path")
    assert error.value.code == "experimental_component"


def test_optional_target_is_registered_and_removed_without_residuals(security_checkout):
    base = security_plan(security_checkout)
    enabled = security_plan(security_checkout, probe=True)
    web = enabled["compose"]["services"]["web"]
    assert json.loads(web["environment"]["XOC_WEB_TARGETS"]) == [{"id": "sample", "service": "lab-target", "port": 8080}]
    assert "lab-target" in web["depends_on"]
    (security_checkout / "presets/with-probe.yaml").write_text(yaml.safe_dump({
        "schema_version": "xoc.preset/0.1.0", "components": ["security-path", "fixture-security-probe"]}))
    removed = plan(security_checkout, preset="with-probe", allow_fixtures=True, allow_experimental=True,
                   without=["fixture-security-probe"])
    assert removed["compose"]["services"] == base["compose"]["services"]
    assert removed["compose"]["networks"] == base["compose"]["networks"]
    assert json.loads(base["compose"]["services"]["web"]["environment"]["XOC_WEB_TARGETS"]) == []
    assert set(base["compose"]["services"]) == {"platform", "fw", "ips", "web"}


def test_production_preset_never_discovers_test_fixture(security_checkout):
    with pytest.raises(XocError) as error:
        plan(security_checkout, preset="security-path", include=["fixture-security-probe"], allow_experimental=True)
    assert error.value.code == "unknown_component"


@pytest.mark.parametrize("role,key,value,code", [
    ("fw", "cap_add", ["NET_ADMIN", "NET_RAW"], "security_privileges"),
    ("ips", "cap_add", ["SYS_ADMIN"], "schema_violation"),
    ("web", "sysctls", {"net.ipv4.ip_forward": "1"}, "security_forwarding"),
    ("fw", "network_mode", "host", "schema_violation"),
    ("fw", "privileged", True, "schema_violation"),
    ("web", "volumes", ["/var/run/docker.sock:/var/run/docker.sock"], "schema_violation"),
    ("web", "read_only", False, "schema_violation"),
    ("fw", "ports", [{"target": 8080, "published": 8080, "host_ip": "127.0.0.1", "protocol": "tcp"}], "security_privileges"),
    ("ips", "networks", {"int": {}}, "security_topology"),
])
def test_device_privileges_and_path_are_fixed(security_checkout, role, key, value, code):
    path = security_checkout / "components/security-path/compose.yaml"
    fragment = yaml_document(path); fragment["services"][role][key] = value
    path.write_text(yaml.safe_dump(fragment))
    with pytest.raises(XocError) as error:
        security_plan(security_checkout)
    assert error.value.code == code


def test_extension_cannot_claim_core_device_privileges(security_checkout):
    folder = security_checkout / "modules.d/security-path"
    folder.parent.mkdir()
    shutil.move(security_checkout / "components/security-path", folder)
    manifest = yaml_document(folder / "component.yaml"); manifest["kind"] = "module"
    (folder / "module.yaml").write_text(yaml.safe_dump(manifest)); (folder / "component.yaml").unlink()
    with pytest.raises(XocError) as error:
        security_plan(security_checkout)
    assert error.value.code == "schema_violation"


def test_backend_must_belong_to_declaring_component(security_checkout):
    path = security_checkout / "tests/fixtures/modules/security-probe/module.yaml"
    manifest = yaml_document(path); manifest["http_targets"][0]["service"] = "platform"
    path.write_text(yaml.safe_dump(manifest))
    with pytest.raises(XocError) as error:
        security_plan(security_checkout, probe=True)
    assert error.value.code == "invalid_http_target"


def test_static_address_collision_is_rejected(security_checkout):
    path = security_checkout / "tests/fixtures/modules/security-probe/compose.yaml"
    fragment = yaml_document(path); fragment["services"]["lab-client"]["networks"]["ext"]["ipv4_address"] = "10.20.30.1"
    path.write_text(yaml.safe_dump(fragment))
    with pytest.raises(XocError) as error:
        security_plan(security_checkout, probe=True)
    assert error.value.code == "address_conflict"


@pytest.mark.parametrize("address", ["10.20.30.254", "10.20.30.0", "10.20.30.255", "10.20.99.10"])
def test_static_endpoint_must_be_usable_in_its_subnet(security_checkout, address):
    path = security_checkout / "tests/fixtures/modules/security-probe/compose.yaml"
    fragment = yaml_document(path); fragment["services"]["lab-client"]["networks"]["ext"]["ipv4_address"] = address
    path.write_text(yaml.safe_dump(fragment))
    with pytest.raises(XocError) as error:
        security_plan(security_checkout, probe=True)
    assert error.value.code == "invalid_network_address"


def test_selected_networks_cannot_overlap(security_checkout):
    compose = security_plan(security_checkout)["compose"]
    compose["networks"]["dmz"] = copy.deepcopy(compose["networks"]["ext"])
    with pytest.raises(XocError) as error:
        check_addresses(compose)
    assert error.value.code == "subnet_overlap"


def test_web_render_contains_only_current_selection():
    render = runpy.run_path(str(ROOT / "components/security-path/web/start.py"))["render"]
    selected, page, learner = render('[{"id":"sample","service":"lab-target","port":8080}]')
    assert "ServerName sample.xoc.test" in selected
    assert "http://lab-target:8080/" in selected
    assert "sample.xoc.test:8080" in page
    assert learner == ""
    empty, page, learner = render("[]")
    assert "lab-target" not in empty and "sample.xoc.test" not in page
    assert "ProxyPass" not in empty and learner == ""


def test_reviewed_targets_get_learner_vhosts_behind_the_ingress():
    render = runpy.run_path(str(ROOT / "components/security-path/web/start.py"))["render"]
    _, _, learner = render(json.dumps([{"id": "juice", "service": "juiceshop", "port": 3000, "public": True},
                                       {"id": "sample", "service": "lab-target", "port": 8080, "public": False}]))
    assert "<VirtualHost *:8443>" in learner and "ServerName juice.xoc.range" in learner
    assert "http://juiceshop:3000/" in learner and "RemoteIPInternalProxy 10.20.30.20" in learner
    assert "sample" not in learner and "lab-target" not in learner


def test_suricata_config_includes_required_yaml_version_and_inline_policy():
    render = runpy.run_path(str(ROOT / "components/security-path/ips/configure.py"))["render"]
    rendered = render({"run-as": {"user": "suricata"}})
    assert rendered.startswith("%YAML 1.1\n---\n")
    config = yaml.safe_load(rendered)
    assert config["stream"]["inline"] is True and config["nfq"]["fail-open"] is False
    assert "run-as" not in config and config["rule-files"] == ["probe.rules"]


@pytest.mark.parametrize("value", [
    [{"id": "bad\nInclude /tmp/evil", "service": "lab-target", "port": 8080}],
    [{"id": "sample", "service": "http://other/", "port": 8080}],
    [{"id": "sample", "service": "lab-target", "port": True}],
    [{"id": "sample", "service": "lab-target", "port": 0}],
    [{"id": "sample", "service": "lab-target", "port": 8080, "raw_config": "evil"}],
    [{"id": "sample", "service": "lab-target", "port": 8080, "public": "yes"}],
    [{"id": "sample", "service": "lab-target", "port": 8080}] * 2,
])
def test_web_configuration_rejects_injection_and_invalid_targets(value):
    render = runpy.run_path(str(ROOT / "components/security-path/web/start.py"))["render"]
    with pytest.raises(ValueError):
        render(json.dumps(value))


@pytest.fixture
def target_checkout(security_checkout):
    for relative in ("components/target-juice", "components/target-dvwa"):
        shutil.copytree(ROOT / relative, security_checkout / relative)
    return security_checkout


def test_practice_targets_are_published_only_through_the_waf(target_checkout):
    result = plan(target_checkout, preset="security-path", allow_experimental=True, include=["target-juice", "target-dvwa"])
    services = result["compose"]["services"]
    for name in ("juiceshop", "dvwa"):
        assert services[name]["networks"] == ["int"] and "ports" not in services[name]
        assert services[name]["cap_drop"] == ["ALL"]
    targets = json.loads(services["web"]["environment"]["XOC_WEB_TARGETS"])
    assert {t["id"]: t.get("public") for t in targets} == {"dvwa": True, "juice": True}
    assert {"juiceshop", "dvwa"} <= set(services["web"]["depends_on"])
    removed = plan(target_checkout, preset="security-path", allow_experimental=True, include=["target-juice"])["compose"]["services"]
    assert "dvwa" not in removed and "dvwa" not in removed["web"]["environment"]["XOC_WEB_TARGETS"]


@pytest.mark.parametrize("change", [
    lambda s: s.update(ports=[{"target": 3000, "published": 3000, "host_ip": "0.0.0.0", "protocol": "tcp"}]),
    lambda s: s.update(networks=["int", "ext"]),
    lambda s: s.update(cap_add=["NET_ADMIN"]),
    lambda s: s.update(volumes=["/:/host"]),
    lambda s: s.update(security_opt=[]),
])
def test_practice_target_fragment_rejects_extra_privileges(target_checkout, change):
    path = target_checkout / "components/target-juice/compose.yaml"
    fragment = yaml.safe_load(path.read_text())
    change(fragment["services"]["juiceshop"])
    path.write_text(yaml.safe_dump(fragment))
    with pytest.raises(XocError):
        plan(target_checkout, preset="security-path", allow_experimental=True, include=["target-juice"])


def test_devices_filter_before_they_route():
    # Forwarding is enabled when the namespace is created. A device that sets
    # its route before loading its table forwards uninspected traffic meanwhile.
    text = (Path(__file__).resolve().parents[1] / 'components/security-path/runtime/entrypoint.sh').read_text()
    for role, table in (('fw', '/etc/xoc/fw.nft'), ('ips', '/etc/xoc/ips.nft')):
        body = text[text.index(f'  {role})'):]
        body = body[:body.index(';;')]
        assert body.index(f'nft -f {table}') < body.index('ip route replace')
        if role == 'ips':
            assert body.index(f'nft -f {table}') < body.index('suricata -T')
            assert 'queue num 0 bypass' not in (Path(__file__).resolve().parents[1] / 'components/security-path/ips/rules.nft').read_text()


def test_networks_keep_the_kt66_address_plan(security_checkout):
    compose = security_plan(security_checkout)["compose"]
    subnets = {name: network["ipam"]["config"][0]["subnet"] for name, network in compose["networks"].items() if "ipam" in network}
    assert subnets == {"ext": "10.20.30.0/24", "pipe": "10.20.31.0/24", "dmz": "10.20.32.0/24", "int": "10.20.40.0/24",
                       "office": "10.20.70.0/24"}
    assert compose["networks"]["int"]["internal"] is True
    assert compose["networks"]["int"]["ipam"]["config"][0]["ip_range"] == "10.20.40.128/25"
    assert compose["services"]["web"]["networks"] == {"dmz": {"ipv4_address": "10.20.32.80"}, "int": {"ipv4_address": "10.20.40.80"}}
    assert compose["services"]["fw"]["networks"]["ext"] == {"ipv4_address": "10.20.30.1"}


def test_learner_vhosts_also_answer_to_the_live_fire_lab_domain(tmp_path):
    """ADR 0011: with a licensed learner domain, dvwa.alice.lab reaches the same target."""
    module = runpy.run_path(str(ROOT / "components/security-path/web/start.py"))
    targets = json.dumps([{"id": "dvwa", "service": "dvwa", "port": 80, "public": True}])
    _, _, learner = module["render"](targets, ["alice.lab"])
    assert "ServerName dvwa.xoc.range" in learner and "ServerAlias dvwa.alice.lab" in learner
    path = tmp_path / "learner-domains.json"
    for content, expected in [('["alice.lab"]', ["alice.lab"]), ('["www.naver.com", "bob.test"]', ["bob.test"]),
                              ('["x.lab\\nInclude /tmp/evil"]', []), ('{"a": 1}', []), ("not json", [])]:
        path.write_text(content)
        assert module["learner_domains"](path) == expected, content
    assert module["learner_domains"](tmp_path / "missing.json") == []


@pytest.fixture
def office_checkout(security_checkout):
    for name in ("office-pc", "siem", "management"):
        shutil.copytree(ROOT / "components" / name, security_checkout / "components" / name)
    return security_checkout


def test_office_network_hangs_off_the_ips_and_carries_the_office_pc(office_checkout):
    """ADR 0012: staff PCs sit on their own network behind the IPS (the kt66 user zone range)."""
    security_checkout = office_checkout
    compose = plan(security_checkout, preset="security-path", include=["office-pc", "siem", "management"],
                   allow_experimental=True)["compose"]
    assert compose["services"]["ips"]["networks"]["office"] == {"ipv4_address": "10.20.70.1"}
    pc = compose["services"]["office-pc"]
    assert pc["networks"] == {"office": {"ipv4_address": "10.20.70.21"}}
    # The PC is on the office network only: no backend, no host port.
    assert "ports" not in pc and "NET_RAW" not in pc["cap_add"] and "SYS_ADMIN" not in pc["cap_add"]
    # The Manager's agent address is on the dmz; its other ports stay on the backend network.
    assert compose["services"]["siem"]["networks"] == {"int": {}, "dmz": {"ipv4_address": "10.20.32.100"}}
    assert {"target": 2222, "published": 2222, "host_ip": "0.0.0.0", "protocol": "tcp"} in compose["services"]["ingress"]["ports"]


def test_office_pc_fragment_rejects_other_privileges(office_checkout):
    security_checkout = office_checkout
    path = security_checkout / "components/office-pc/compose.yaml"
    fragment = yaml.safe_load(path.read_text())
    fragment["services"]["office-pc"]["networks"]["int"] = {}
    path.write_text(yaml.safe_dump(fragment))
    with pytest.raises(XocError) as error:
        plan(security_checkout, preset="security-path", include=["office-pc"], allow_experimental=True)
    assert error.value.code == "schema_violation"


def test_office_rules_reach_only_the_web_gateway_and_the_agent_port():
    ips = (ROOT / "components/security-path/ips/rules.nft").read_text()
    office = [line.strip() for line in ips.splitlines() if "10.20.70." in line and not line.strip().startswith("#")]
    assert office == [
        "ip saddr 10.20.30.0/24 ip daddr 10.20.70.21 tcp dport 22 counter name inspected queue num 0",
        "ip saddr 10.20.70.21 ip daddr 10.20.30.0/24 tcp sport 22 counter name inspected queue num 0",
        "ip saddr 10.20.70.0/24 ip daddr 10.20.32.80 tcp dport 8080 counter name inspected queue num 0",
        "ip saddr 10.20.32.80 ip daddr 10.20.70.0/24 tcp sport 8080 counter name inspected queue num 0",
        "ip saddr 10.20.70.0/24 ip daddr 10.20.32.100 tcp dport 1514 accept",
        "ip saddr 10.20.32.100 ip daddr 10.20.70.0/24 tcp sport 1514 ct state established accept",
        "ip saddr 10.20.70.0/24 ip daddr 10.20.32.100 tcp dport 1514 masquerade",
    ]
    assert "policy drop" in ips
    fw = (ROOT / "components/security-path/fw/rules.nft").read_text()
    assert "ip saddr 10.20.30.0/24 ip daddr 10.20.30.1 tcp dport 2222 dnat to 10.20.70.21:22" in fw
    # Nothing forwards from the office network to the backend network.
    assert "10.20.40." not in ips and "10.20.40." not in fw


def test_office_account_is_a_hash_and_the_ingress_forwards_ssh(tmp_path, monkeypatch):
    monkeypatch.setattr("os.chown", lambda *a, **k: None)
    from xocrange.office_setup import account
    from xocrange.ui_setup import ingress_config
    config = {}
    account(tmp_path, config)
    assert config["office_username"] == "student" and len(config["office_password"]) >= 16
    hashed = (tmp_path / "password.hash").read_text().strip()
    assert hashed.startswith("$6$") and config["office_password"] not in hashed
    assert (tmp_path / "username").read_text() == "student\n"
    again = dict(config)
    account(tmp_path, again)
    assert again["office_password"] == config["office_password"]
    text = ingress_config("192.0.2.10")
    assert "bind :2222" in text and "server fw 10.20.30.1:2222" in text and text.count("mode tcp") == 2
