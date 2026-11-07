#!/usr/bin/env python3
"""Small, stdlib-only helpers for the privileged installer; no implicit host writes."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import tempfile


FILES = ("install.sh", "pyproject.toml", "README.md")
DIRECTORIES = ("src/xocrange", "components", "presets", "contracts", "modules.d",
               "scripts", "tests/fixtures/modules/security-probe", "assets/branding")


def source_files(root):
    paths = [root / name for name in FILES]
    for name in DIRECTORIES:
        base = root / name
        if any(path.is_symlink() for path in (base, *base.parents) if path != root and root in path.parents):
            raise ValueError("Source directories must not be symlinks")
        paths.extend(base.rglob("*"))
    result = {}
    for path in sorted(set(paths)):
        relative = path.relative_to(root)
        if any(part in ("__pycache__", ".local", ".git") or part.endswith(".egg-info") for part in relative.parts):
            continue
        if path.is_symlink():
            raise ValueError(f"Source symlink is not allowed: {relative}")
        if path.is_file() and path.suffix not in (".pyc", ".pyo"):
            result[str(relative)] = hashlib.sha256(path.read_bytes()).hexdigest()
    for name in FILES:
        if name not in result:
            raise ValueError(f"Incomplete installation source: {name}")
    return result


def snapshot(source, releases):
    source, releases = source.resolve(), releases.resolve()
    manifest = source_files(source)
    digest = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
    target = releases / digest
    if target.exists():
        if target.is_symlink() or source_files(target) != manifest:
            raise ValueError("An existing release differs from its source hash")
        return target
    releases.mkdir(parents=True, exist_ok=True, mode=0o755)
    temporary = Path(tempfile.mkdtemp(prefix=".staging-", dir=releases))
    try:
        for name in manifest:
            destination = temporary / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / name, destination)
            destination.chmod(0o755 if name == "install.sh" else 0o644)
        for directory in temporary.rglob("*"):
            if directory.is_dir():
                directory.chmod(0o755)
        if source_files(temporary) != manifest:
            raise ValueError("Installation source changed during copying")
        (temporary / "release-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        temporary.chmod(0o755)
        temporary.rename(target)
    except BaseException:
        shutil.rmtree(temporary)
        raise
    return target


def data_path(value):
    path = Path(value)
    if not re.fullmatch(r"/[A-Za-z0-9_/-]+", value) or ".." in path.parts or path == Path("/"):
        raise ValueError("Data directory must be a simple absolute path")
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise ValueError("Data directory must not traverse symlinks")
    if path.exists() and (not path.is_dir() or path.stat().st_mode & 0o022):
        raise ValueError("Data directory must not be writable by other users")
    return path


def docker_config(text, directory):
    config = json.loads(text or "{}")
    if not isinstance(config, dict):
        raise ValueError("Docker daemon configuration must be an object")
    expected = str(data_path(directory) / "docker")
    if config.get("data-root", expected) != expected:
        raise ValueError("Refusing to relocate an existing Docker data-root")
    # Preserve unrelated options; do not change networking or firewall backends.
    config["data-root"] = expected
    config.setdefault("log-driver", "local")
    if config["log-driver"] == "local":
        options = config.setdefault("log-opts", {})
        options.setdefault("max-size", "10m")
        options.setdefault("max-file", "3")
    return json.dumps(config, indent=2, sort_keys=True) + "\n"


def containerd_config(text, directory):
    expected = str(data_path(directory) / "containerd")
    # Only edit the top-level root, leaving plugin tables and distro settings intact.
    parts = re.split(r"(?m)^(?=\s*\[)", text or "version = 2\n", maxsplit=1)
    matches = list(re.finditer(r"(?m)^\s*root\s*=\s*([\"'])([^\n]*?)\1\s*(?:#[^\n]*)?$", parts[0]))
    if len(matches) > 1 or ("root" in parts[0] and re.search(r"(?m)^\s*root\s*=", parts[0]) and not matches):
        raise ValueError("Unsupported containerd root configuration")
    if matches and matches[0][2] not in ("/var/lib/containerd", expected):
        raise ValueError("Refusing to relocate an existing containerd data root")
    line = "root = " + json.dumps(expected) + "\n"
    if matches:
        parts[0] = parts[0][:matches[0].start()] + line + parts[0][matches[0].end():]
    else:
        parts[0] = line + parts[0]
    return "".join(parts)


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    copy = commands.add_parser("snapshot")
    copy.add_argument("source", type=Path); copy.add_argument("releases", type=Path)
    configure = commands.add_parser("storage")
    configure.add_argument("directory"); configure.add_argument("output", type=Path)
    configure.add_argument("--docker", type=Path, default=Path("/etc/docker/daemon.json"))
    configure.add_argument("--containerd", type=Path, default=Path("/etc/containerd/config.toml"))
    args = parser.parse_args()
    if args.command == "snapshot":
        print(snapshot(args.source, args.releases))
    else:
        docker = docker_config(args.docker.read_text() if args.docker.exists() else "", args.directory)
        containerd = containerd_config(args.containerd.read_text() if args.containerd.exists() else "", args.directory)
        args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
        (args.output / "daemon.json").write_text(docker)
        (args.output / "config.toml").write_text(containerd)


if __name__ == "__main__":
    main()
