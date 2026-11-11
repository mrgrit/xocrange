import json
from pathlib import Path
import subprocess
import sys

from xocrange.cli import main

ROOT = Path(__file__).resolve().parents[1]


def test_cli_plan_and_doctor_have_no_output_side_effects(checkout, capsys):
    assert main(["--root", str(checkout), "plan"]) == 0
    assert json.loads(capsys.readouterr().out)["lock"]["selected"] == ["platform"]
    assert not (checkout / ".local").exists()
    assert main(["--root", str(checkout), "doctor"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["checks"]["docker_daemon"] == "not-checked"
    assert not (checkout / ".local").exists()


def test_invalid_plan_creates_no_output(checkout, capsys):
    assert main(["--root", str(checkout), "plan", "--include", "unknown", "--output", "bad"]) == 2
    result = capsys.readouterr()
    assert result.out == ""
    assert json.loads(result.err)["error"]["code"] == "unknown_component"
    assert not (checkout / ".local").exists()


def test_normalize_validate_roundtrip_and_safe_error(tmp_path, capsys):
    args = ["events", "normalize", "--source", "suricata", "--input", str(ROOT / "tests/fixtures/events/suricata-alert.json"),
            "--tenant-id", "community", "--range-id", "range-01", "--source-id", "sensor-01",
            "--evidence-ref", "fixture://record/001", "--observed-at", "2026-11-07T03:35:00Z"]
    assert main(args) == 0
    normalized = tmp_path / "events.json"
    normalized.write_text(capsys.readouterr().out)
    assert main(["events", "validate", "--input", str(normalized)]) == 0
    assert json.loads(capsys.readouterr().out) == {"valid": True, "events": 1}
    normalized.write_text('{"secret":"DO-NOT-PRINT"}')
    assert main(["events", "validate", "--input", str(normalized)]) == 2
    captured = capsys.readouterr()
    assert "DO-NOT-PRINT" not in captured.err
    assert "Traceback" not in captured.err


def test_checkout_entry_point():
    result = subprocess.run([sys.executable, str(ROOT / "bin/xoc"), "--version"], capture_output=True, text=True)
    assert result.returncode == 0
    assert result.stdout.strip() == "xoc 0.1.0"


def test_learner_targets_list_only_selected_reviewed_targets():
    from xocrange.cli import learner_targets
    root = Path(__file__).resolve().parents[1]
    result = learner_targets(root, ['platform', 'security-path', 'target-juice', 'fixture-security-probe'], '192.0.2.10')
    assert result['hosts_line'] == '192.0.2.10 juice.xoc.range'
    assert [t['url'] for t in result['targets']] == ['https://juice.xoc.range/']
    assert learner_targets(root, ['platform'], 'xoc.example.test')['hosts_line'] is None
