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
