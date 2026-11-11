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
    fragment = yaml_document(path); fragment["services"]["lab-client"]["networks"]["ext"]["ipv4_address"] = "172.29.10.1"
    path.write_text(yaml.safe_dump(fragment))
    with pytest.raises(XocError) as error:
        security_plan(security_checkout, probe=True)
    assert error.value.code == "address_conflict"


@pytest.mark.parametrize("address", ["172.29.10.254", "172.29.10.0", "172.29.10.255", "172.29.99.10"])
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
    assert "http://juiceshop:3000/" in learner and "RemoteIPInternalProxy 172.29.10.20" in learner
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
