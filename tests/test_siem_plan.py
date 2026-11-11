from pathlib import Path
import runpy
import shutil
from types import SimpleNamespace

import pytest
import yaml

from xocrange.errors import XocError
from xocrange.planner import plan

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def siem_checkout(tmp_path):
    for directory in ('components/platform','components/security-path','components/siem','presets'):
        shutil.copytree(ROOT/directory,tmp_path/directory)
    return tmp_path


def test_siem_is_optional_and_volumes_are_private(siem_checkout):
    base = plan(siem_checkout,preset='security-path',allow_experimental=True)
    added = plan(siem_checkout,preset='security-path',include=['siem'],allow_experimental=True)
    assert 'siem' not in base['compose']['services']
    assert set(added['compose']['volumes']) == {'fw-logs','ips-logs','web-logs','siem-logs','siem-etc','siem-api','siem-queue','siem-var','siem-config'}
    assert 'siem-api:/var/ossec/api/configuration' in added['compose']['services']['siem']['volumes']
    assert 'siem-queue:/var/ossec/queue' in added['compose']['services']['siem']['volumes']
    assert 'ports' not in added['compose']['services']['siem']


@pytest.mark.parametrize('change', [{'volumes':['/var/run/docker.sock:/var/run/docker.sock']},
                                    {'cap_add':['SYS_ADMIN']}, {'privileged':True}, {'network_mode':'host'}])
def test_siem_cannot_expand_its_host_privileges(siem_checkout,change):
    path=siem_checkout/'components/siem/compose.yaml'
    fragment=yaml.safe_load(path.read_text());fragment['services']['siem'].update(change);path.write_text(yaml.safe_dump(fragment))
    with pytest.raises(XocError):
        plan(siem_checkout,preset='security-path',include=['siem'],allow_experimental=True)


def manager_volumes(tmp_path,monkeypatch,mounts):
    module=runpy.run_path(str(ROOT/'components/siem/bootstrap.py'))
    seed=tmp_path/'seed'
    for relative in module['VOLUMES']:(seed/relative).mkdir(parents=True)
    (seed/'var/run').mkdir();(seed/'var/db').mkdir();(seed/'var/db/global.db').write_text('seed')
    root=tmp_path/'ossec'
    for relative in mounts:(root/relative).mkdir(parents=True)
    monkeypatch.setattr(type(root),'is_mount',lambda path:path in {root/m for m in mounts})
    monkeypatch.setattr(module['os'],'chown',lambda *args:None)
    return module['seed_volumes'],root,seed


def test_manager_seeds_fresh_volume_holding_only_nested_mount_points(tmp_path,monkeypatch):
    # Compose mounts the /var/ossec/var/run tmpfs inside the siem-var volume, so
    # Docker leaves an empty run/ mount point in a brand-new volume.
    fragment=yaml.safe_load((ROOT/'components/siem/compose.yaml').read_text())['services']['siem']
    assert any(entry.startswith('/var/ossec/var/run:') for entry in fragment['tmpfs'])
    seed_volumes,root,_=manager_volumes(tmp_path,monkeypatch,['var/run'])
    seed_volumes(root,tmp_path/'seed')
    assert (root/'var/db/global.db').read_text()=='seed'
    assert all((root/relative/'.xoc-initialized').is_file() for relative in ('etc','api/configuration','queue','var'))


def test_manager_never_overwrites_unmarked_volume_with_state(tmp_path,monkeypatch):
    seed_volumes,root,_=manager_volumes(tmp_path,monkeypatch,['var/run'])
    (root/'var/db').mkdir();(root/'var/db/global.db').write_text('existing')
    with pytest.raises(SystemExit,match='not empty: var'):
        seed_volumes(root,tmp_path/'seed')
    assert (root/'var/db/global.db').read_text()=='existing'
    assert not (root/'var/.xoc-initialized').exists()


def test_audit_rule_setup_resumes_partial_install_without_flushing():
    configure=runpy.run_path(str(ROOT/'scripts/configure-audit.py'))['configure']
    import shlex
    desired=[]
    for line in (ROOT/'components/siem/audit.rules').read_text().splitlines():
        args=shlex.split(line);args[1]=str(Path(args[1]).resolve());desired.append(shlex.join(args))
    calls=[]
    def run(args,**kwargs):
        calls.append(args)
        return SimpleNamespace(stdout='\n'.join(desired[:2]))
    configure(ROOT/'components/siem/audit.rules',run=run)
    assert len(calls)==2 and calls[1][-1]=='xoc_probe' and '-D' not in calls[1]
    calls.clear()
    def complete(args,**kwargs):
        calls.append(args)
        return SimpleNamespace(stdout='\n'.join(desired))
    configure(ROOT/'components/siem/audit.rules',run=complete)
    assert calls==[['auditctl','-l']]


def test_audit_symlink_watch_migrates_and_persists_real_executable(tmp_path):
    configure=runpy.run_path(str(ROOT/'scripts/configure-audit.py'))['configure']
    executable=tmp_path/'gnutrue';executable.write_text('')
    link=tmp_path/'true';link.symlink_to(executable)
    rules=tmp_path/'source.rules';rules.write_text(f'-w {link} -p x -k xoc_probe\n')
    installed=tmp_path/'installed.rules';calls=[]
    def run(args,**kwargs):
        calls.append(args);return SimpleNamespace(stdout=rules.read_text())
    configure(rules,run=run,output=installed)
    assert calls==[['auditctl','-l'],['auditctl','-W',str(link),'-p','x','-k','xoc_probe'],['auditctl','-w',str(executable),'-p','x','-k','xoc_probe']]
    assert installed.read_text()==f'-w {executable} -p x -k xoc_probe\n'
    assert installed.stat().st_mode & 0o777==0o600


def test_audit_conflicting_owned_key_fails_before_changing_any_rule(tmp_path):
    configure=runpy.run_path(str(ROOT/'scripts/configure-audit.py'))['configure']
    rules=tmp_path/'source.rules';rules.write_text('-w /etc/xocrange -p wa -k xoc_config\n-w /usr/bin/true -p x -k xoc_probe\n')
    calls=[]
    def run(args,**kwargs):
        calls.append(args);return SimpleNamespace(stdout='-w /unrelated -p x -k xoc_probe')
    with pytest.raises(ValueError):configure(rules,run=run)
    assert calls==[['auditctl','-l']]


def test_audit_failed_delete_requires_observed_absence(tmp_path):
    configure=runpy.run_path(str(ROOT/'scripts/configure-audit.py'))['configure']
    rules=tmp_path/'source.rules';rules.write_text('-w /etc/xocrange -p wa -k xoc_config\n')
    calls=[]
    def run(args,**kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=255 if '-W' in args else 0,stdout=rules.read_text() if len(calls)==1 else '')
    configure(rules,remove=True,run=run)
    assert calls[-1]==['auditctl','-l']
    def stuck(args,**kwargs):
        return SimpleNamespace(returncode=255 if '-W' in args else 0,stdout=rules.read_text())
    import subprocess
    with pytest.raises(subprocess.CalledProcessError):configure(rules,remove=True,run=stuck)
