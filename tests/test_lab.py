import json
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest
import yaml

from xocrange import lab
from xocrange.errors import XocError
from xocrange.planner import plan, write_plan

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def lab_checkout(checkout):
    shutil.copytree(ROOT / "components/security-path", checkout / "components/security-path")
    result = plan(checkout, preset="security-path", allow_experimental=True)
    write_plan(checkout, "test-lab", result)
    return checkout


def test_modified_compose_is_rejected_before_docker(lab_checkout, monkeypatch):
    path = lab_checkout / ".local/plans/test-lab/compose.yaml"
    compose = yaml.safe_load(path.read_text()); compose["services"]["fw"]["privileged"] = True
    path.write_text(yaml.safe_dump(compose))
    monkeypatch.setattr(lab, "Docker", lambda *_: pytest.fail("Docker must not be called"))
    with pytest.raises(XocError) as error:
        lab.run_lab(lab_checkout, "test-lab", "up", True)
    assert error.value.code == "modified_compose"


def test_modified_build_input_requires_new_plan(lab_checkout):
    path = lab_checkout / "components/security-path/fw/rules.nft"
    path.write_text(path.read_text() + "\n# new policy\n")
    with pytest.raises(XocError) as error:
        lab.checked_plan(lab_checkout, "test-lab")
    assert error.value.code == "stale_plan"


def test_execution_requires_explicit_dedicated_vm(lab_checkout, monkeypatch):
    monkeypatch.setattr(lab, "host_check", lambda *_: pytest.fail("No host probe before explicit execution flag"))
    with pytest.raises(XocError) as error:
        lab.run_lab(lab_checkout, "test-lab", "up")
    assert error.value.code == "isolated_vm_required"


def test_blocked_preflight_never_starts_containers(lab_checkout, monkeypatch):
    monkeypatch.setattr(lab, "host_check", lambda *_: {"status": "blocked", "checks": {"dedicated_daemon": False}})
    monkeypatch.setattr(lab.Docker, "run", lambda *_a, **_k: pytest.fail("No mutation after failed preflight"))
    assert lab.run_lab(lab_checkout, "test-lab", "up", True)["status"] == "blocked"


def test_boot_start_uses_validated_local_images_without_build_or_pull(lab_checkout, monkeypatch):
    monkeypatch.setattr(lab, "host_check", lambda *_: {"status": "ready", "checks": {"dedicated_daemon": True}})
    calls = []
    monkeypatch.setattr(lab.Docker, "run", lambda self, args, **kwargs: calls.append(args))
    assert lab.run_lab(lab_checkout, "test-lab", "start", True)["status"] == "started"
    assert calls == [["up", "--detach", "--no-build", "--pull", "never"]]


def test_cleanup_works_after_bridge_configuration_changes(lab_checkout, monkeypatch):
    checks = {key: True for key in ("ubuntu_26_04", "virtual_machine", "local_daemon", "linux_daemon", "rootful_daemon", "dedicated_daemon")}
    checks["bridge_netfilter_disabled"] = False
    monkeypatch.setattr(lab, "host_check", lambda *_: {"status": "blocked", "checks": checks})
    calls = []
    monkeypatch.setattr(lab.Docker, "run", lambda self, args, **kwargs: calls.append(args))
    assert lab.run_lab(lab_checkout, "test-lab", "down", True)["status"] == "stopped"
    assert calls == [["down"]]


@pytest.fixture
def fake_host(tmp_path, monkeypatch):
    for name, content in (("etc/os-release", 'ID=ubuntu\nVERSION_ID="26.04"\n'),
                          ("proc/sys/net/bridge/bridge-nf-call-iptables", "0\n")):
        path = tmp_path / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(content)
    (tmp_path / "sys/module/nfnetlink_queue").mkdir(parents=True)
    monkeypatch.setattr(lab, "Path", lambda value: tmp_path / value.lstrip("/"))
    monkeypatch.setattr(lab.subprocess, "run", lambda args, **_: SimpleNamespace(returncode=0, stdout="kvm\n" if args[0] == "systemd-detect-virt" else "[]"))
    state = {"containers": [], "endpoint": "unix:///var/run/docker.sock", "security_options": []}

    class Engine:
        def run(self, args):
            if args[0] == "context": return state["endpoint"]
            if args[0] == "info": return json.dumps({"OSType": "linux", "SecurityOptions": state["security_options"]})
            if args[0] == "ps": return "\n".join(json.dumps(item) for item in state["containers"])
            if args[0] == "network": return ""
            if args[0] == "compose": return "Docker Compose version 5"
            raise AssertionError(args)

    return tmp_path, state, Engine()


def test_clean_dedicated_vm_passes_prerequisites(fake_host):
    _, _, engine = fake_host
    assert lab.host_check(engine, "xoc-core-security-path")["status"] == "ready"


def test_foreign_containers_block_execution(fake_host):
    _, state, engine = fake_host
    state["containers"] = [{"Labels": "com.docker.compose.project=kt66"}]
    result = lab.host_check(engine, "xoc-core-security-path")
    assert result["status"] == "blocked" and not result["checks"]["dedicated_daemon"]


@pytest.mark.parametrize("endpoint", ["ssh://other-host", "tcp://localhost:2375"])
def test_remote_daemon_is_not_used(fake_host, endpoint):
    _, state, engine = fake_host; state["endpoint"] = endpoint
    report = lab.host_check(engine, "xoc-core-security-path")
    assert report["status"] == "blocked" and not report["checks"]["local_daemon"]


def test_rootless_and_wrong_os_are_reported(fake_host):
    root, state, engine = fake_host
    (root / "etc/os-release").write_text('ID=ubuntu\nVERSION_ID="22.04"\n')
    state["security_options"] = ["name=rootless"]
    report = lab.host_check(engine, "xoc-core-security-path")
    assert not report["checks"]["ubuntu_26_04"] and not report["checks"]["rootful_daemon"]


def test_log_reader_accepts_multiline_and_adjacent_records():
    result = list(lab.records(' {"a":\n1}\n\n {"b":2} '))
    assert [json.loads(item) for item in result] == [{"a": 1}, {"b": 2}]
    with pytest.raises(ValueError):
        list(lab.records('{"incomplete":'))
