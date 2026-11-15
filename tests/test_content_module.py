"""The Community content bundle ships in contents/ and installs only if it matches module.json (ADR-0009)."""
import json
from pathlib import Path
import shutil

import pytest

from xocrange import content_module as m

ROOT = Path(__file__).resolve().parents[1]


def bundle(tmp_path, payload=None):
    payload = payload or {'guides/test.json': b'{"version": 1}'}
    root = tmp_path / 'contents'
    for name, data in payload.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes(data)
    (root / 'module.json').write_text(json.dumps({'schema_version': 'xoc.content-module/0.1.0', 'id': 'community-academy',
                                                  'files': {k: m.sha(v) for k, v in payload.items()}}))
    return root


def test_repository_bundle_matches_its_manifest():
    out = m.summary(ROOT)
    assert out['status'] == 'verified' and out['module'] == 'community-academy' and out['files'] >= 360
    assert len(list((ROOT / 'contents/battle-scenarios').glob('xoc-*.yaml'))) == 15


def test_bundle_with_authoring_material_verifies(tmp_path):
    root = bundle(tmp_path)
    (root / 'README.md').write_text('notes'); (root / 'scripts').mkdir(); (root / 'scripts/tool.py').write_text('')
    (root / 'scripts/__pycache__').mkdir(); (root / 'scripts/__pycache__/tool.cpython-314.pyc').write_bytes(b'')
    assert m.verify(root) == 1


@pytest.mark.parametrize('case', ['edited', 'undeclared', 'missing', 'stray', 'symlink', 'traversal', 'oversized'])
def test_bundle_that_differs_from_its_manifest_is_refused(tmp_path, case):
    root = bundle(tmp_path)
    if case == 'edited':
        (root / 'guides/test.json').write_text('changed without regenerating module.json')
    elif case == 'undeclared':
        (root / 'guides/extra.json').write_text('{}')
    elif case == 'missing':
        (root / 'guides/test.json').unlink()
    elif case == 'stray':
        (root / 'secrets.txt').write_text('not part of the bundle')
    elif case == 'symlink':
        (root / 'guides/link.json').symlink_to('/etc/passwd')
    elif case == 'traversal':
        raw = json.loads((root / 'module.json').read_text()); raw['files'] = {'../escape': '0' * 64}
        (root / 'module.json').write_text(json.dumps(raw))
    else:
        root = bundle(tmp_path / 'big', {'guides/big.bin': b'x' * (m.MAX_FILE + 1)})
    with pytest.raises(ValueError):
        m.verify(root)


def test_bundle_directory_cannot_be_a_symlink(tmp_path):
    real = bundle(tmp_path)
    shutil.move(real, tmp_path / 'real'); (tmp_path / 'contents').symlink_to(tmp_path / 'real', target_is_directory=True)
    with pytest.raises(ValueError, match='regular directory'):
        m.verify(tmp_path / 'contents')
