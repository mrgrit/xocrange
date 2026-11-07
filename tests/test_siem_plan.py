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
    assert set(added['compose']['volumes']) == {'fw-logs','ips-logs','web-logs','siem-logs'}
    assert added['compose']['services']['siem']['volumes'] == ['siem-logs:/var/ossec/logs']
    assert 'ports' not in added['compose']['services']['siem']


@pytest.mark.parametrize('change', [{'volumes':['/var/run/docker.sock:/var/run/docker.sock']},
                                    {'cap_add':['SYS_ADMIN']}, {'privileged':True}, {'network_mode':'host'}])
def test_siem_cannot_expand_its_host_privileges(siem_checkout,change):
    path=siem_checkout/'components/siem/compose.yaml'
    fragment=yaml.safe_load(path.read_text());fragment['services']['siem'].update(change);path.write_text(yaml.safe_dump(fragment))
    with pytest.raises(XocError):
        plan(siem_checkout,preset='security-path',include=['siem'],allow_experimental=True)


def test_audit_rule_setup_resumes_partial_install_without_flushing():
    configure=runpy.run_path(str(ROOT/'scripts/configure-audit.py'))['configure']
    desired=(ROOT/'components/siem/audit.rules').read_text().splitlines()
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
