import json
import shutil
from pathlib import Path

import pytest
import yaml

from xocrange.documents import yaml_document
from xocrange.errors import XocError
from xocrange.planner import catalog, compatible, plan, write_plan

ROOT = Path(__file__).resolve().parents[1]


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(value))


def module(root, identifier="extension", **changes):
    manifest = yaml_document(root / "tests/fixtures/modules/echo/module.yaml")
    manifest.update(id=identifier, kind="module", provides=[f"extension.{identifier}"])
    manifest.update(changes)
    folder = root / "modules.d" / identifier
    save(folder / "module.yaml", manifest)
    fragment = yaml_document(root / "tests/fixtures/modules/echo/compose.yaml")
    fragment["services"] = {identifier.lower(): fragment["services"]["fixture-echo"]}
    save(folder / "compose.yaml", fragment)
    return folder


def expect(code, operation):
    with pytest.raises(XocError) as raised:
        operation()
    assert raised.value.code == code


def test_bootstrap_plan_determinism_and_portable_lock(checkout, tmp_path_factory):
    first = plan(checkout)
    assert first == plan(checkout)
    assert first["lock"]["selected"] == ["platform"]
    assert first["compose"]["services"]["platform"]["ports"][0]["host_ip"] == "127.0.0.1"
    other = tmp_path_factory.mktemp("relocated") / "repo"
    shutil.copytree(checkout, other)
    assert first["lock"] == plan(other)["lock"]
    health = checkout / "components/platform/health.py"
    health.write_text(health.read_text() + "\n# changed build input\n")
    assert first["lock"]["plan_id"] != plan(checkout)["lock"]["plan_id"]


def test_fixture_is_opt_in_and_dependencies_are_resolved(checkout):
    assert "fixture-echo" not in catalog(checkout)
    expect("unknown_component", lambda: plan(checkout, include=["fixture-echo"]))
    result = plan(checkout, include=["fixture-echo"], allow_fixtures=True)
    assert result["lock"]["selected"] == ["platform", "fixture-echo"]
    assert set(result["compose"]["services"]) == {"platform", "fixture-echo"}


def test_module_dependencies_auto_selected_and_exclusions_obeyed(checkout):
    module(checkout, "dependency")
    module(checkout, "extension", requires={"components": ["dependency"], "capabilities": ["extension.dependency"]})
    result = plan(checkout, include=["extension"])
    assert result["lock"]["selected"].index("dependency") < result["lock"]["selected"].index("extension")
    expect("required_component", lambda: plan(checkout, include=["extension"], without=["dependency"]))
    expect("required_component", lambda: plan(checkout, without=["platform"]))


def test_planned_components_cannot_generate_fake_deployment():
    assert catalog(ROOT)["security-path"]["manifest"]["status"] == "experimental"
    expect("component_not_ready", lambda: plan(ROOT, preset="community-security"))


@pytest.mark.parametrize("changes,code", [
    ({"commercial": True}, "commercial_unavailable"),
    ({"minimum_tier": "live-fire"}, "commercial_unavailable"),
    ({"minimum_tier": "joint-force"}, "commercial_unavailable"),
    ({"core": ">=0.2.0 <0.3.0"}, "core_incompatible"),
    ({"core": "latest"}, "invalid_version_range"),
    ({"requires": {"components": ["missing"], "capabilities": []}}, "missing_dependency"),
    ({"requires": {"components": ["extension"], "capabilities": []}}, "dependency_cycle"),
    ({"requires": {"components": [], "capabilities": ["missing"]}}, "missing_capability"),
    ({"conflicts": ["platform"]}, "component_conflict"),
    ({"contracts": {"C1": "99.0.0"}}, "schema_violation"),
])
def test_invalid_component_relationships(checkout, changes, code):
    module(checkout, **changes)
    expect(code, lambda: plan(checkout, include=["extension"]))


def test_paid_id_cannot_claim_to_be_a_community_module(checkout):
    module(checkout, "M1", commercial=False, minimum_tier="community")
    expect("commercial_unavailable", lambda: plan(checkout, include=["M1"]))


@pytest.mark.parametrize("mutation,code", [
    (lambda f: f["services"].update(platform=f["services"].pop("extension")), "service_conflict"),
    (lambda f: f["networks"]["int"].update(internal=False), "network_conflict"),
    (lambda f: f["services"]["extension"].update(networks=["ot"]), "undeclared_network"),
    (lambda f: f["services"]["extension"].update(depends_on=["missing"]), "missing_service"),
    (lambda f: f["services"]["extension"].update(depends_on=["extension"]), "service_cycle"),
    (lambda f: f["services"]["extension"].update(privileged=True), "schema_violation"),
    (lambda f: f["services"]["extension"].update(volumes=["/:/host"]), "schema_violation"),
    (lambda f: f["services"]["extension"].update(user="0:0"), "schema_violation"),
    (lambda f: f["services"]["extension"].update(environment={"UNDECLARED": "x"}), "undeclared_config"),
    (lambda f: f["services"]["extension"].update(command=["${SECRET}"]), "environment_interpolation"),
])
def test_invalid_fragments_are_rejected(checkout, mutation, code):
    folder = module(checkout)
    fragment = yaml_document(folder / "compose.yaml")
    mutation(fragment)
    save(folder / "compose.yaml", fragment)
    expect(code, lambda: plan(checkout, include=["extension"]))


@pytest.mark.parametrize("host", ["127.0.0.1", "0.0.0.0", "::"])
def test_port_overlaps_include_wildcard_bindings(checkout, host):
    folder = module(checkout)
    fragment = yaml_document(folder / "compose.yaml")
    fragment["services"]["extension"]["ports"] = [{"target": 1234, "published": 18080, "host_ip": host, "protocol": "tcp"}]
    save(folder / "compose.yaml", fragment)
    expect("port_conflict", lambda: plan(checkout, include=["extension"]))


def test_duplicate_config_and_component_ids(checkout):
    module(checkout, "one", config_keys=["APP_SETTING"])
    folder = module(checkout, "two", config_keys=["APP_SETTING"])
    expect("config_conflict", lambda: plan(checkout, include=["one", "two"]))
    data = yaml_document(folder / "module.yaml")
    data["id"] = "one"
    save(folder / "module.yaml", data)
    expect("duplicate_component", lambda: catalog(checkout))


def test_path_escape_and_untracked_build_input(checkout, tmp_path_factory):
    folder = module(checkout, compose="../outside.yaml")
    expect("path_escape", lambda: plan(checkout, include=["extension"]))
    module(checkout)
    outside = tmp_path_factory.mktemp("outside") / "compose.yaml"
    outside.write_text((folder / "compose.yaml").read_text())
    (folder / "compose.yaml").unlink()
    (folder / "compose.yaml").symlink_to(outside)
    expect("path_escape", lambda: plan(checkout, include=["extension"]))
    (checkout / "components/platform/secret.txt").write_text("do not send to Docker")
    expect("untracked_build_input", lambda: plan(checkout))


@pytest.mark.parametrize("raw", ["id: one\nid: two\n", "value: &anchor [a]\nother: *anchor\n", "!!python/object/apply:os.system ['false']\n"])
def test_yaml_duplicate_alias_and_object_tags_are_rejected(tmp_path, raw):
    path = tmp_path / "input.yaml"
    path.write_text(raw)
    with pytest.raises(XocError):
        yaml_document(path)


def test_plan_output_refuses_overwrite_and_path_escape(checkout, tmp_path_factory):
    result = plan(checkout)
    output = write_plan(checkout, "bootstrap", result)
    assert json.loads((output / "plan.lock.json").read_text()) == result["lock"]
    assert yaml_document(output / "compose.yaml") == result["compose"]
    expect("output_exists", lambda: write_plan(checkout, "bootstrap", result))
    expect("path_escape", lambda: write_plan(checkout, "../../../escape", result))
    outside = tmp_path_factory.mktemp("output-outside")
    (checkout / ".local/plans/link").symlink_to(outside, target_is_directory=True)
    expect("path_escape", lambda: write_plan(checkout, "link/new", result))


def test_numeric_version_range_uses_numeric_order():
    assert compatible(">=0.1.0 <0.2.0")
    assert compatible(">=0.2.0 <0.11.0", "0.10.0")
    assert not compatible("=0.2.0")
