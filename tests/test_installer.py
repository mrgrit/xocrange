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
