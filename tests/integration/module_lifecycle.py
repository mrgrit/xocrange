#!/usr/bin/env python3
"""Dedicated-VM K10/K11 exercise; no modifications to an unrelated installation."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys

from xocrange import operations as ops
from xocrange.lifecycle import copy_source
from xocrange.events import Context, normalize
from xocrange.documents import validate
from siem_lifecycle import common_identity

p=argparse.ArgumentParser();p.add_argument('--package',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
p.add_argument('--isolated-vm',action='store_true');a=p.parse_args()
if not a.isolated_vm or os.geteuid()!=0:p.error('Root and --isolated-vm are required')
if a.output.exists():p.error('Use a new output path')
a.output.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
checks={};steps=[]

def run(args, label, success=True):
    path=a.output.parent/(label+'.log')
    with path.open('w') as log:
        result=subprocess.run(args,stdout=log,stderr=subprocess.STDOUT,timeout=1800)
    steps.append({'step':label,'returncode':result.returncode})
    if (result.returncode==0)!=success:raise RuntimeError('Unexpected outcome: '+label)


def login():
    state=ops.installed();root=Path(state['release'])
    spec=importlib.util.spec_from_file_location('gateway',root/'scripts/verify-platform.py')
    gateway=importlib.util.module_from_spec(spec);spec.loader.exec_module(gateway)
    file=ops.STATE/'platform/credentials.json';secret=json.loads(file.read_text())
    session=gateway.Session(secret['public_host']);code,body,_,_=session.login('admin',secret.get('admin_password',secret['bootstrap_password']))
    assert code==200
    if body.get('must_change_password'):
        password='K10-Acceptance!'+secrets.token_urlsafe(24)
        assert session.request('/core/api/password',{'current_password':secret['bootstrap_password'],'password':password})[0]==200
        secret['admin_password']=password;ops.save(file,secret)
    return session


def phase(label, present):
    session=login();state=ops.installed()
    checks[label+'_selected']=('fixture-lifecycle' in state['selected'])==present
    checks[label+'_status_route']=session.request('/core/api/modules/fixture-lifecycle')[0]==(200 if present else 404)
    panels=session.request('/core/api/session')[1]['navigation']
    checks[label+'_navigation']=any(p['component_id']=='fixture-lifecycle' for p in panels)==present
    names=subprocess.check_output(['docker','ps','--format','{{.Label "com.docker.compose.service"}}'],text=True).splitlines()
    checks[label+'_container']=('fixture-lifecycle' in names)==present
    checks[label+'_identities_and_policies']=common_identity(ops.PROJECT)==identity
    session.request('/core/api/logout',{})


def save():
    ops.save(a.output,{'status':'passed' if checks and all(checks.values()) else 'failed','checks':checks,'steps':steps,
                       'source_release':ops.installed()['release'],'finished_at':datetime.now(timezone.utc).isoformat()})

try:
    initial=ops.installed();session=login();session.request('/core/api/logout',{})
    identity=common_identity(ops.PROJECT)
    phase('before',False)
    run(['xoc','module','add','--package',str(a.package)],'add')
    phase('added',True)
    state=ops.installed();run(['xoc','lab','start','--plan',state['plan'],'--isolated-vm'],'up')
    event=subprocess.check_output(['docker','exec','xoc-core-security-path-fixture-lifecycle-1','python','-B','-c',"import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8080/event').read().decode())"],text=True).encode()
    now=datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
    normalized=normalize('suricata',event,Context('community','local','fixture-lifecycle','xoc-evidence:'+hashlib.sha256(event).hexdigest(),now))
    checks['fixture_status_api_and_c1_event']=bool(normalized) and all(validate(e,'c1-event') for e in normalized)
    run(['xoc','module','remove','fixture-lifecycle'],'remove')
    phase('removed',False)
    state=ops.installed();run(['xoc','lab','start','--plan',state['plan'],'--isolated-vm'],'up-after-remove')
    run(['xoc','module','add','--package',str(a.package)],'re-add')
    phase('reinstalled',True)
    run(['xoc','module','remove','fixture-lifecycle'],'final-remove')
    phase('final',False)
    before=ops.installed()
    candidate=a.output.parent/'failed-candidate';candidate.mkdir(mode=0o700)
    copy_source(Path(before['release']),candidate)
    file=candidate/'scripts/verify-management.py'
    file.write_text("raise SystemExit('K11 controlled acceptance failure')\n"+file.read_text())
    run(['xoc','update','--source',str(candidate)],'failed-update',success=False)
    checks['failed_update_restored_release']=ops.installed()['release']==before['release']
    checks['failed_update_restored_plan']=ops.installed()['plan']==before['plan']
    checks['failed_update_restored_accounts_policies']=common_identity(ops.PROJECT)==identity
    checks['failure_recorded']=json.loads((ops.STATE/'last-attempt.json').read_text())['status']=='failed'
    checks['rollback_recorded']=json.loads((ops.STATE/'install-operation.json').read_text())['status']=='rolled-back'
    session=login();checks['management_after_rollback']=session.request('/core/api/devices')[0]==200;session.request('/core/api/logout',{})
    shutil.rmtree(candidate)
    checks['exercise_completed']=True
    save()
except BaseException:
    checks['exercise_completed']=False
    raise
finally:
    save()
print(json.dumps({'status':'passed' if all(checks.values()) else 'failed','checks':len(checks),'output':str(a.output)},indent=2))
raise SystemExit(not all(checks.values()))
