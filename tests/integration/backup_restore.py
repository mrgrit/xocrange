#!/usr/bin/env python3
"""Exercise portable backup, corruption rejection and real DB/settings restore."""
import argparse
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time
from xocrange import operations as ops
from siem_lifecycle import common_identity

p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--isolated-vm',action='store_true');a=p.parse_args()
if not a.isolated_vm or os.geteuid()!=0 or a.output.exists():p.error('Use a new private output on the isolated VM')
a.output.mkdir(mode=0o700);checks={}
def run(args,name,success=True):
    for attempt in range(12):
        path=a.output/(name+'.log')
        with path.open('w') as f:r=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT,timeout=1800)
        if '"code": "operation_busy"' not in path.read_text():break
        time.sleep(5)
    assert (r.returncode==0)==success,name
marker=ops.STATE/'platform/k11-restore-marker';marker.write_text('before-backup\n');marker.chmod(0o600)
identity=common_identity(ops.PROJECT);before=ops.installed()
backup=a.output/'portable'
try:
    run(['xoc','backup','create',str(backup)],'create')
    run(['xoc','backup','verify',str(backup)],'verify')
    manifest=ops.verify_backup(backup)
    checks['portable_images_saved']=manifest['portable'] and (backup/'images.tar').stat().st_size>0
    corrupt=a.output/'corrupt';corrupt.mkdir(mode=0o700)
    for f in backup.iterdir():
        if f.name!='manifest.json':os.link(f,corrupt/f.name)
    bad=json.loads((backup/'manifest.json').read_text());bad['files']['source.tar.gz']['sha256']='0'*64
    ops.save(corrupt/'manifest.json',bad)
    run(['xoc','backup','restore',str(corrupt)],'reject-corrupt',False)
    checks['corruption_does_not_change_state']=ops.installed()==before and common_identity(ops.PROJECT)==identity
    checks['corruption_does_not_stop_core']=subprocess.run(['systemctl','is-active','--quiet','xocrange-core']).returncode==0
    marker.write_text('after-backup\n')
    volume=ops.volume_paths()['platform-data']
    with sqlite3.connect(volume/'control.sqlite3') as db:db.execute("UPDATE control_devicepolicy SET version=version+1,write_enabled=1 WHERE device='fw'")
    checks['actual_database_change']=common_identity(ops.PROJECT)!=identity
    run(['xoc','backup','restore',str(backup)],'restore')
    checks['settings_restored']=marker.read_text()=='before-backup\n'
    checks['accounts_and_policy_db_restored']=common_identity(ops.PROJECT)==identity
    checks['release_restored']=ops.installed()['release']==before['release']
    checks['exact_images_restored']=all(ops.image_inventory(ops.installed())[n]['id']==v['id'] for n,v in manifest['images'].items())
    checks['core_acceptance_after_restore']=subprocess.run(['systemctl','is-active','--quiet','xocrange-core']).returncode==0
    journal=json.loads((ops.STATE/'restore-operation.json').read_text())
    checks['pre_restore_recovery_retained']=journal['status']=='complete' and bool(journal['recovery']) and Path(journal['recovery'],'manifest.json').is_file()
    checks['exercise_completed']=True
finally:
    checks.setdefault('exercise_completed',False)
    ops.save(a.output/'result.json',{'status':'passed' if all(checks.values()) else 'failed','checks':checks,
                                   'source_release':before['release'],'backup':str(backup)})
print(json.dumps({'status':'passed' if all(checks.values()) else 'failed','checks':len(checks)}))
raise SystemExit(not all(checks.values()))
