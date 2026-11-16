"""An update keeps installed external module packages the new source does not ship."""
import os

import pytest

from xocrange.errors import XocError
from xocrange.lifecycle import carry_modules


def package(root, identifier, text='v1'):
    folder = root / 'modules.d' / identifier
    folder.mkdir(parents=True)
    (folder / 'module.yaml').write_text(f'id: {identifier}\n# {text}\n')
    return folder


def test_installed_packages_are_carried_only_when_selected_and_missing(tmp_path):
    release, staged = tmp_path / 'release', tmp_path / 'staged'
    package(release, 'm15-assessor'); package(release, 'removed-module')
    package(staged, 'shipped', 'new'); package(release, 'shipped', 'old')
    carry_modules(release, staged, {'m15-assessor', 'shipped', 'platform'})
    assert (staged / 'modules.d/m15-assessor/module.yaml').is_file()
    assert not (staged / 'modules.d/removed-module').exists()
    assert 'new' in (staged / 'modules.d/shipped/module.yaml').read_text()


def test_symlinked_installed_package_is_refused(tmp_path):
    release, staged = tmp_path / 'release', tmp_path / 'staged'
    folder = package(release, 'm15-assessor')
    os.symlink('/etc/passwd', folder / 'link')
    with pytest.raises(XocError):
        carry_modules(release, staged, {'m15-assessor'})


@pytest.mark.parametrize('image,ok', [
    ('192.168.16.101:5443/xoc/m15-assessor:0.1.0@sha256:' + 'a' * 64, True),
    ('registry.example/xoc/m15-assessor@sha256:' + 'b' * 64, True),
    ('192.168.16.101:5443/xoc/m15-assessor:0.1.0', False),        # a tag can move
    ('m15-assessor@sha256:' + 'a' * 64, False),                  # no registry
    ('registry.example/xoc/x@sha256:abc', False),
])
def test_package_images_must_be_pinned_by_digest(image, ok):
    from xocrange.lifecycle import check_package_images
    fragment = {'services': {'m15-assessor': {'image': image}}}
    if ok:
        check_package_images(fragment)
    else:
        with pytest.raises(XocError) as error:
            check_package_images(fragment)
        assert error.value.code == 'module_image_unpinned'
    check_package_images({'services': {'built': {'build': {'context': '.', 'dockerfile': 'Dockerfile'}}}})   # source packages still build


def _staged(tmp_path):
    from pathlib import Path
    import shutil
    repo = Path(__file__).resolve().parents[1]
    staged = tmp_path / 'staged'
    shutil.copytree(repo / 'components', staged / 'components', ignore=shutil.ignore_patterns('__pycache__'))
    (staged / 'modules.d').mkdir()
    source = repo / 'tests/fixtures/packages/lifecycle'
    return staged, source


def test_upgrade_replaces_an_installed_package(tmp_path):
    import shutil
    from xocrange.lifecycle import stage_package
    staged, source = _staged(tmp_path)
    with pytest.raises(XocError) as error:                       # nothing installed yet
        stage_package(source, staged, replace=True)
    assert error.value.code == 'module_not_package'
    assert stage_package(source, staged) == 'fixture-lifecycle'
    with pytest.raises(XocError) as error:
        stage_package(source, staged)
    assert error.value.code == 'module_exists'
    newer = tmp_path / 'newer'
    shutil.copytree(source, newer, ignore=shutil.ignore_patterns('__pycache__'))
    (newer / 'server.py').write_text((newer / 'server.py').read_text() + '\n# v2\n')
    assert stage_package(newer, staged, replace=True) == 'fixture-lifecycle'
    assert '# v2' in (staged / 'modules.d/fixture-lifecycle/server.py').read_text()


def test_upgrade_cannot_replace_a_core_component(tmp_path):
    import shutil
    import yaml
    from xocrange.lifecycle import stage_package
    staged, source = _staged(tmp_path)
    fake = tmp_path / 'fake'
    shutil.copytree(source, fake, ignore=shutil.ignore_patterns('__pycache__'))
    manifest = yaml.safe_load((fake / 'module.yaml').read_text()); manifest['id'] = 'siem'
    (fake / 'module.yaml').write_text(yaml.safe_dump(manifest))
    with pytest.raises(XocError) as error:
        stage_package(fake, staged, replace=True)
    assert error.value.code == 'module_not_package'


def test_upgrade_with_source_updates_core_and_replaces_the_package_in_one_plan(tmp_path, monkeypatch):
    """xoc module upgrade --package P --source S: the new Core source, the other installed packages
    carried over, the module replaced by its new package, planned by the staged release's planner."""
    import shutil
    from pathlib import Path
    from xocrange import lifecycle
    repo = Path(__file__).resolve().parents[1]
    source = repo / 'tests/fixtures/packages/lifecycle'
    release = tmp_path / 'release'
    shutil.copytree(source, release / 'modules.d/fixture-lifecycle', ignore=shutil.ignore_patterns('__pycache__'))
    import yaml
    other = release / 'modules.d/fixture-other'
    shutil.copytree(source, other, ignore=shutil.ignore_patterns('__pycache__'))
    manifest = yaml.safe_load((other / 'module.yaml').read_text()); manifest['id'] = 'fixture-other'
    (other / 'module.yaml').write_text(yaml.safe_dump(manifest))
    newer = tmp_path / 'newer'
    shutil.copytree(source, newer, ignore=shutil.ignore_patterns('__pycache__'))
    (newer / 'server.py').write_text((newer / 'server.py').read_text() + '\n# v2\n')
    seen = {}

    def copy_source(src, staged):
        seen['source'] = src
        shutil.copytree(repo / 'components', staged / 'components', ignore=shutil.ignore_patterns('__pycache__'))
        (staged / 'modules.d').mkdir()

    def release_plan(staged, chosen):
        seen['modules'] = sorted(p.name for p in (staged / 'modules.d').iterdir())
        seen['server'] = (staged / 'modules.d/fixture-lifecycle/server.py').read_text()
        return {'lock': {'selected': sorted(chosen), 'plan_id': 'p'}}

    monkeypatch.setattr(lifecycle.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(lifecycle.ops, 'STATE', tmp_path)
    monkeypatch.setattr(lifecycle.ops, 'installed', lambda: {'release': str(release), 'selected': ['fixture-lifecycle', 'fixture-other', 'platform']})
    monkeypatch.setattr(lifecycle, 'copy_source', copy_source)
    monkeypatch.setattr(lifecycle, 'release_plan', release_plan)
    report = lifecycle.change(repo, 'upgrade', None, newer, tmp_path / 'core-src', preview=True)
    assert report['status'] == 'validated' and seen['source'] == tmp_path / 'core-src'
    assert seen['modules'] == ['fixture-lifecycle', 'fixture-other'] and '# v2' in seen['server']
    with pytest.raises(XocError) as error:
        lifecycle.change(repo, 'add', None, newer, tmp_path / 'core-src', preview=True)
    assert error.value.code == 'usage'
