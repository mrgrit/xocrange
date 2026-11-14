"""Stage a reviewed selection/package, then delegate its transaction to install.sh."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from .documents import yaml_document, validate, within
from .errors import XocError
from .planner import catalog, plan
from . import operations as ops

DEFAULT_OPTIONAL = {'siem','siem-ui','console-fw','console-ips','console-waf','portal','noc','academy-reader'}
REQUIRED = {'platform','security-path','management','fixture-security-probe'}


def selection_arguments(selected):
    return [arg for name in sorted(set(selected)-REQUIRED) for arg in ('--include', name)] + [arg for name in sorted(DEFAULT_OPTIONAL-set(selected)) for arg in ('--without', name)]


RELEASE_PLAN = r"""
import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1] + '/src')
from xocrange.errors import XocError
from xocrange.planner import plan
try:
    result = plan(Path(sys.argv[1]), preset='security-path', include=json.loads(sys.argv[2]), allow_fixtures=True, allow_experimental=True)
except XocError as exc:
    print(json.dumps({'error': {'code': exc.code, 'message': str(exc)}})); sys.exit(2)
print(json.dumps({'lock': result['lock']}))
"""


def release_plan(staged, chosen):
    """Plan a staged release with its own planner.

    The installed code knows only the installed topology and policy; when a
    release changes a reviewed network or policy together with the components,
    the old planner would reject a valid release. install.sh revalidates with
    the same new code before any mutation.
    """
    import sys
    result = subprocess.run([sys.executable, '-I', '-B', '-c', RELEASE_PLAN, str(staged), json.dumps(sorted(chosen))],
                            capture_output=True, text=True, timeout=300)
    try:
        value = json.loads(result.stdout.strip().splitlines()[-1])
    except (IndexError, ValueError):
        raise XocError('release_plan_failed', 'The staged release could not plan its selection.') from None
    if 'error' in value:
        raise XocError(value['error']['code'], value['error']['message'])
    return value


def carry_modules(release, staged, chosen):
    """Keep installed external module packages across an update when the new source
    does not ship them (they were added with `xoc module add --package`)."""
    for identifier in sorted(chosen):
        installed, target = release/'modules.d'/identifier, staged/'modules.d'/identifier
        if (installed/'module.yaml').is_file() and not target.exists():
            if any(p.is_symlink() for p in (installed, *installed.rglob('*'))):
                raise XocError('module_symlink', 'Installed module packages must contain regular files only.')
            shutil.copytree(installed, target)


def copy_source(source, destination):
    # Reuse the installer's explicitly bounded release contents, never .git/.env.
    import importlib.util, sys
    spec = importlib.util.spec_from_file_location('xoc_install_snapshot', source/'scripts/install-support.py')
    support = importlib.util.module_from_spec(spec)
    # Runs as root against the operator's checkout: never leave a root-owned
    # scripts/__pycache__ behind in it.
    previous, sys.dont_write_bytecode = sys.dont_write_bytecode, True
    try:
        spec.loader.exec_module(support)
    finally:
        sys.dont_write_bytecode = previous
    for relative in support.source_files(source):
        target = destination/relative; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source/relative, target)


def change(root, action, identifier=None, package=None, source=None, *, preview=False):
    if os.geteuid() != 0:
        raise XocError('root_required', 'Module and update operations require sudo.')
    current = ops.installed()
    chosen = set(current['selected'])
    stage_base = ops.STATE/'staging'; stage_base.mkdir(exist_ok=True, mode=0o700)
    staged = Path(tempfile.mkdtemp(prefix='selection-', dir=stage_base))
    try:
        copy_source(source or Path(current['release']), staged)
        if action == 'add' and package:
            package = package.absolute()
            if any(p.is_symlink() for p in (package, *package.parents)) or any(p.is_symlink() for p in package.rglob('*')):
                raise XocError('module_symlink', 'Module packages must contain regular, declared local files.')
            manifest = validate(yaml_document(package/'module.yaml'), 'manifest')
            if manifest['kind'] != 'module':
                raise XocError('invalid_kind', 'Installable packages must declare kind: module.')
            declared = {package/'module.yaml', *(within(package, name) for name in [manifest.get('compose','compose.yaml'), *manifest['build_inputs']])}
            if {p for p in package.rglob('*') if p.is_file()} != declared:
                raise XocError('module_undeclared_file', 'Every module package file must be declared in its manifest.')
            identifier = manifest['id']
            if identifier in catalog(staged, allow_fixtures=True):
                raise XocError('module_exists', 'A package already owns this module identifier.')
            if sum(p.stat().st_size for p in package.rglob('*') if p.is_file()) > 128*1024**2:
                raise XocError('module_size', 'Module source exceeds the 128 MiB installation limit.')
            shutil.copytree(package, staged/'modules.d'/identifier)
        if action == 'add':
            if not identifier:
                raise XocError('missing_arguments', 'Choose a catalog ID or a module --package directory.')
            chosen.add(identifier)
        elif action == 'remove':
            if identifier in REQUIRED:
                raise XocError('required_component', 'This profile requires the selected Core service.')
            if identifier not in chosen:
                raise XocError('module_not_selected', 'The module is not selected.')
            chosen.remove(identifier)
            # Dependencies are checked before removing code. No implicit cascade.
            plan(staged, preset='security-path', include=chosen, without=[identifier], allow_fixtures=True, allow_experimental=True)
            entry = catalog(staged, allow_fixtures=True)[identifier]
            if entry['manifest']['kind'] == 'module':
                shutil.rmtree(entry['path'].parent)
        if action == 'update':
            carry_modules(Path(current['release']), staged, chosen)
            selected = release_plan(staged, chosen)
        else:
            selected = plan(staged, preset='security-path', include=chosen, allow_fixtures=True, allow_experimental=True)
        report = {'action':action, 'before':current['selected'], 'after':selected['lock']['selected'],
                  'plan_id':selected['lock']['plan_id'], 'preserves_data':True}
        if preview:
            return dict(report, status='validated')
        host = json.loads((ops.STATE/'platform/credentials.json').read_text())['public_host']
        expected = Path(current['release']).name+':'+current['plan'].removeprefix('install-')
        args = ['bash', str(staged/'install.sh'), '--expected-install', expected, '--public-host', host, '--data-dir', current['data_directory'], *selection_arguments(selected['lock']['selected'])]
        # The child owns the common installer lock; it revalidates before mutation.
        result = subprocess.run(args)
        if result.returncode:
            raise XocError('module_transaction_failed', 'The installation failed; inspect last-attempt.json and the rollback journal.')
        return dict(report, status='installed', release=ops.installed()['release'])
    finally:
        shutil.rmtree(staged)
