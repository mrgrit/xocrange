#!/usr/bin/env python3
"""Verify the Community content bundle shipped in contents/ (ADR-0009).

contents/module.json lists the path and SHA-256 of every installable file under the payload
directories. Paid content packs live outside Core (mrgrit/xocrange_contents) and are not read here.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re

PAYLOAD = {'academy', 'battle-scenarios', 'catalog', 'guides'}
# Authoring material kept beside the payload (incl. tool bytecode); never installed, never served.
AUTHORING = {'README.md', 'NOTICE', 'requirements.txt', 'provenance', 'scripts'}
MAX_EXPANDED = 128 * 1024**2
MAX_FILE = 8 * 1024**2


def sha(data):
    return hashlib.sha256(data).hexdigest()


def manifest(raw):
    if len(raw) > 1024**2:
        raise ValueError('Content manifest exceeds its size limit')
    value = json.loads(raw)
    if value.get('schema_version') != 'xoc.content-module/0.1.0' or value.get('id') != 'community-academy':
        raise ValueError('Unsupported content module')
    files = value.get('files')
    if not isinstance(files, dict) or not 1 <= len(files) <= 4096:
        raise ValueError('Invalid content file inventory')
    for name, digest in files.items():
        parts = PurePosixPath(name).parts
        if (not parts or parts[0] not in PAYLOAD or '..' in parts
                or str(PurePosixPath(name)) != name or '\\' in name
                or not isinstance(digest, str) or not re.fullmatch('[a-f0-9]{64}', digest)):
            raise ValueError('Invalid content file path or hash')
    return files


def verify(directory):
    """Return the manifest's file count, or raise ValueError if the bundle differs from it."""
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('Content bundle must be a regular directory: ' + str(directory))
    actual = set()
    for p in directory.rglob('*'):
        if p.is_symlink():
            raise ValueError('Content bundle cannot contain symlinks')
        relative = p.relative_to(directory)
        if p.is_file() and relative.parts[0] in PAYLOAD:
            actual.add(str(PurePosixPath(*relative.parts)))
        elif p.is_file() and str(relative) != 'module.json' and relative.parts[0] not in AUTHORING:
            raise ValueError('Content bundle contains an undeclared file: ' + str(relative))
    files = manifest((directory / 'module.json').read_bytes())
    if actual != set(files):
        missing, extra = sorted(set(files) - actual), sorted(actual - set(files))
        raise ValueError(f'Content bundle differs from module.json (missing {missing[:3]}, undeclared {extra[:3]}); '
                         'run contents/scripts/content-module.py manifest after editing')
    total = 0
    for name, digest in files.items():
        p = directory / name
        size = p.stat().st_size
        total += size
        if size > MAX_FILE or total > MAX_EXPANDED or sha(p.read_bytes()) != digest:
            raise ValueError('Content file size or checksum differs: ' + name)
    return len(files)


def summary(root):
    directory = Path(root).resolve() / 'contents'
    raw = (directory / 'module.json').read_bytes()
    return {'status': 'verified', 'module': json.loads(raw)['id'], 'manifest_sha256': sha(raw),
            'files': verify(directory)}
