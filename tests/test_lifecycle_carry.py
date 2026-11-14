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
