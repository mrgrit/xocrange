#!/usr/bin/env python3
"""Fetch the separately versioned, data-only content module before installation."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import tempfile
import urllib.request

PAYLOAD = {'academy', 'battle-scenarios', 'catalog', 'guides'}
MAX_ARCHIVE = 64 * 1024**2
MAX_EXPANDED = 128 * 1024**2
MAX_FILE = 8 * 1024**2


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_lock(path):
    if path.stat().st_size > 8192:
        raise ValueError('Content lock exceeds its size limit')
    value = json.loads(path.read_bytes())
    if (set(value) != {'schema_version', 'repository', 'commit', 'manifest_sha256'}
            or value['schema_version'] != 'xoc.content-lock/0.1.0'
            or value['repository'] != 'https://github.com/mrgrit/xocrange_contents'
            or not re.fullmatch('[a-f0-9]{40}', value['commit'])
            or not re.fullmatch('[a-f0-9]{64}', value['manifest_sha256'])):
        raise ValueError('Invalid pinned content identity')
    return value


def manifest(raw, lock):
    if len(raw) > 1024**2 or sha(raw) != lock['manifest_sha256']:
        raise ValueError('Content manifest differs from the pinned hash')
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
                or not re.fullmatch('[a-f0-9]{64}', digest)):
            raise ValueError('Invalid content file path or hash')
    return files


def verify(directory, lock):
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('Content cache must be a regular directory')
    for p in directory.rglob('*'):
        if p.is_symlink():
            raise ValueError('Content cache cannot contain symlinks')
    files = manifest((directory / 'module.json').read_bytes(), lock)
    actual = {str(p.relative_to(directory)) for p in directory.rglob('*') if p.is_file()}
    if actual != set(files) | {'module.json', '.content-source.json'}:
        raise ValueError('Content cache contains missing or undeclared files')
    if read_lock(directory / '.content-source.json') != lock:
        raise ValueError('Content cache belongs to a different pinned version')
    total = 0
    for name, digest in files.items():
        p = directory / name
        total += p.stat().st_size
        if p.stat().st_size > MAX_FILE or total > MAX_EXPANDED or sha(p.read_bytes()) != digest:
            raise ValueError('Content file size or checksum differs: ' + name)
    return len(files)


def unpack(archive, destination, lock):
    with tarfile.open(archive, 'r:gz') as bundle:
        index = {}
        prefix = None
        expanded = 0
        for number, item in enumerate(bundle):
            expanded += item.size
            if number >= 8192 or expanded > MAX_EXPANDED or item.size > MAX_FILE:
                raise ValueError('Content archive exceeds its expansion limits')
            parts = PurePosixPath(item.name).parts
            if (not parts or item.name.startswith('/') or '..' in parts or '\\' in item.name
                    or not (item.isfile() or item.isdir())):
                raise ValueError('Unsafe content archive entry')
            if prefix is None:
                prefix = parts[0]
            if parts[0] != prefix:
                raise ValueError('Content archive has multiple roots')
            name = '/'.join(parts[1:])
            if item.isfile():
                if name in index:
                    raise ValueError('Duplicate content archive entry')
                index[name] = item
        item = index.get('module.json')
        if item is None or item.size > 1024**2:
            raise ValueError('Content archive manifest is missing or oversized')
        raw = bundle.extractfile(item).read()
        files = manifest(raw, lock)
        payload = {n for n in index if PurePosixPath(n).parts[0] in PAYLOAD}
        if payload != set(files):
            raise ValueError('Content archive inventory differs from its manifest')
        if sum(index[n].size for n in files) > MAX_EXPANDED:
            raise ValueError('Expanded content exceeds its size limit')
        for name, digest in files.items():
            item = index[name]
            if item.size > MAX_FILE:
                raise ValueError('Content file exceeds its size limit')
            data = bundle.extractfile(item).read()
            if sha(data) != digest:
                raise ValueError('Downloaded content checksum differs: ' + name)
            p = destination / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
        (destination / 'module.json').write_bytes(raw)
        (destination / '.content-source.json').write_text(json.dumps(lock, indent=2) + '\n')
    return verify(destination, lock)


def fetch(root, *, verify_only=False, archive=None):
    root = root.resolve()
    lock = read_lock(root / 'content-lock.json')
    target = root / 'contents'
    previous = None
    if target.exists() or target.is_symlink():
        if target.is_symlink():
            raise ValueError('Content cache cannot be a symlink')
        previous = read_lock(target / '.content-source.json')
        count = verify(target, previous)  # Preserve local edits; never overwrite an unverified tree.
        if previous == lock:
            return {'status': 'verified', 'commit': lock['commit'], 'files': count}
    if verify_only:
        raise ValueError('Pinned content is missing; run scripts/fetch-contents.py')
    with tempfile.TemporaryDirectory(prefix='.content-download-', dir=root) as work:
        work = Path(work)
        source = archive
        if source is None:
            source = work / 'archive.tar.gz'
            url = 'https://codeload.github.com/mrgrit/xocrange_contents/tar.gz/' + lock['commit']
            request = urllib.request.Request(url, headers={'User-Agent': 'xOC-Range-content-installer'})
            with urllib.request.urlopen(request, timeout=90) as response, source.open('wb') as out:
                total = 0
                while block := response.read(1024**2):
                    total += len(block)
                    if total > MAX_ARCHIVE:
                        raise ValueError('Downloaded content exceeds its size limit')
                    out.write(block)
        if source.stat().st_size > MAX_ARCHIVE:
            raise ValueError('Content archive exceeds its size limit')
        staged = work / 'payload'
        staged.mkdir()
        count = unpack(source, staged, lock)
        old = work / 'previous'
        if previous is not None:
            target.rename(old)
        try:
            staged.rename(target)
        except BaseException:
            if old.exists():
                old.rename(target)
            raise
    return {'status': 'installed', 'commit': lock['commit'], 'files': count}


