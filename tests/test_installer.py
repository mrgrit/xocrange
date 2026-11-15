import importlib.util
import json
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("install_support", ROOT / "scripts/install-support.py")
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)


def test_snapshot_is_repeatable_and_excludes_local_credentials(tmp_path):
    source = tmp_path / "source"; source.mkdir()
    for name in support.FILES:
        (source / name).write_text("public source\n")
    (source / ".env").write_text("PRIVATE_SECRET=must-not-copy\n")
    (source / ".local").mkdir(); (source / ".local/private").write_text("private")
    package = source / "src/xocrange"; package.mkdir(parents=True)
    (package / "app.py").write_text("pass\n")
    cache = package / "__pycache__"; cache.mkdir(); (cache / "app.pyc").write_bytes(b"cache")
    target = support.snapshot(source, tmp_path / "releases")
    assert target == support.snapshot(source, tmp_path / "releases")
    assert not (target / ".env").exists() and not (target / ".local").exists()
    assert not (target / "src/xocrange/__pycache__").exists()
    (target / "src/xocrange/app.py").write_text("modified\n")
    with pytest.raises(ValueError, match="differs"):
        support.snapshot(source, tmp_path / "releases")


def test_snapshot_refuses_parent_directory_symlinks(tmp_path):
    source = tmp_path / "source"; source.mkdir()
    external = tmp_path / "external"; (external / "xocrange").mkdir(parents=True)
    (source / "src").symlink_to(external, target_is_directory=True)
    with pytest.raises(ValueError, match="symlinks"):
        support.source_files(source)


def test_storage_settings_preserve_options_and_cover_both_runtimes():
    value = support.docker_config('{"live-restore":true,"log-opts":{"max-file":"5"}}', "/srv/xoc-data")
    config = json.loads(value)
    assert config["data-root"] == "/srv/xoc-data/docker"
    assert config["live-restore"] and config["log-opts"]["max-file"] == "5"
    assert support.docker_config(value, "/srv/xoc-data") == value
    original = 'version = 3\nroot = "/var/lib/containerd"\n[plugins.example]\nroot = "leave-alone"\n'
    changed = support.containerd_config(original, "/srv/xoc-data")
    assert 'root = "/srv/xoc-data/containerd"' in changed
    assert '[plugins.example]\nroot = "leave-alone"' in changed
    assert support.containerd_config(changed, "/srv/xoc-data") == changed


def test_storage_does_not_silently_move_existing_data():
    with pytest.raises(ValueError, match="relocate"):
        support.docker_config('{"data-root":"/old/docker"}', "/srv/xoc-data")
    with pytest.raises(ValueError, match="relocate"):
        support.containerd_config('root = "/old/containerd"\n', "/srv/xoc-data")


@pytest.mark.parametrize("path", ["/", "relative", "/srv/../etc", "/srv/data with spaces", "/srv/data\nother"])
def test_data_paths_reject_unsafe_values(path):
    with pytest.raises(ValueError):
        support.data_path(path)


def test_data_path_cannot_follow_symlink(tmp_path):
    link = tmp_path / "redirect"; link.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match="symlinks"):
        support.data_path(str(link / "data"))


def test_installer_dry_run_does_not_require_root_or_docker():
    result = subprocess.run(["bash", str(ROOT / "install.sh"), "--dry-run"], capture_output=True, text=True)
    assert result.returncode == 0 and "No changes performed" in result.stdout


@pytest.mark.parametrize("args", [["--include"], ["--include", "../../outside"], ["--ref", "main"], ["--unexpected"]])
def test_invalid_installer_options_fail_before_host_operations(args):
    result = subprocess.run(["bash", str(ROOT / "install.sh"), *args], capture_output=True, text=True)
    assert result.returncode == 2 and "[xOC]" not in result.stdout


def test_installer_pauses_apt_timers_and_waits_for_running_upgrade(tmp_path):
    # A libc6 upgrade by unattended-upgrades re-executes systemd and drops the
    # installer's in-flight systemctl jobs; the installer pauses APT timers.
    text = (ROOT / "install.sh").read_text()
    functions = text[text.index("paused_apt_timers=()"):text.index("trap on_exit EXIT\npause_apt_maintenance")]
    tools = tmp_path / "bin"; tools.mkdir()
    log = tmp_path / "systemctl.log"
    (tools / "systemctl").write_text(f"""#!/bin/bash
echo "$*" >> {log}
case "$*" in
  "is-active --quiet apt-daily.timer") exit 0 ;;
  "is-active --quiet apt-daily-upgrade.timer") exit 3 ;;
  "show -p ActiveState --value apt-daily-upgrade.service")
    seen=$(grep -c "apt-daily-upgrade.service" {log})
    if ((seen < 3)); then echo activating; else echo inactive; fi ;;
  "show -p ActiveState --value apt-daily.service") echo inactive ;;
esac
""")
    (tools / "sleep").write_text("#!/bin/sh\n")
    for tool in tools.iterdir():
        tool.chmod(0o755)
    script = "set -Eeuo pipefail\n" + functions + "\npause_apt_maintenance\nresume_apt_maintenance\n"
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                            env={"PATH": f"{tools}:/usr/bin:/bin"})
    assert result.returncode == 0, result.stderr
    calls = log.read_text().splitlines()
    assert "stop apt-daily.timer" in calls and "stop apt-daily-upgrade.timer" not in calls
    assert calls.count("show -p ActiveState --value apt-daily-upgrade.service") == 3
    assert calls[-1] == "start apt-daily.timer"
    assert "Waiting for automatic package maintenance" in result.stdout


@pytest.mark.parametrize("failures,expected", [(1, 0), (99, 1)])
def test_sysmon_start_retries_a_transient_ring_buffer_failure(tmp_path, failures, expected):
    # Sysmon's perf ring buffer needs contiguous pages; a first start can fail
    # with ENOMEM and succeed after memory compaction. Persistent failure still fails.
    text = (ROOT / "scripts/install-telemetry.sh").read_text()
    function = text[text.index("start_sysmon() {"):text.index("if systemctl cat sysmon.service")]
    tools = tmp_path / "bin"; tools.mkdir()
    log = tmp_path / "systemctl.log"; log.write_text("")
    (tools / "systemctl").write_text(f"""#!/bin/bash
echo "$*" >> {log}
starts=$(grep -cE "^(enable --now|restart) sysmon.service" {log})
case "$*" in
  "enable --now sysmon.service"|"restart sysmon.service") ((starts > {failures})) || exit 1 ;;
  "is-active --quiet sysmon.service") ((starts > {failures})) || exit 3 ;;
esac
""")
    (tools / "sleep").write_text("#!/bin/sh\n")
    for tool in tools.iterdir():
        tool.chmod(0o755)
    script = "set -Eeuo pipefail\n" + function + "\nstart_sysmon systemctl enable --now sysmon.service\n"
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                            env={"PATH": f"{tools}:/usr/bin:/bin"})
    assert result.returncode == expected, result.stderr
    calls = log.read_text().splitlines()
    assert calls[0] == "enable --now sysmon.service"
    assert calls.count("restart sysmon.service") == (1 if expected == 0 else 4)


def test_standalone_download_is_removed_once_the_release_holds_the_source():
    # A standalone run (install.sh alone, or --ref) fetches the source into
    # /var/lib/xocrange/download-*; the snapshot copies it, so it must not
    # accumulate across runs (62 MB each on the 0.1.0 RC VM).
    text = (ROOT / "install.sh").read_text()
    snapshot = text.index('install-support.py" snapshot')
    removal = text.index('rm -rf -- "$downloaded"', snapshot)
    assert removal - snapshot < 400
    on_exit = text[text.index("on_exit() {"):text.index("trap on_exit EXIT")]
    assert 'rm -rf -- "$downloaded"' in on_exit
