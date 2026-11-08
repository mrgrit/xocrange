#!/usr/bin/env python3
"""Verify full SIEM deselection/reselection; installation is a separate action.

Checkpoint adds one private, temporary audit watch and a lifecycle API user/search.
Cleanup removes only those test-owned objects. Evidence and volumes stay intact.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import uuid

from siem_lifecycle import (STATE, Installed, fingerprint, installation_lock,
    private_directory, save_new, anchor_integrity, common_identity)
from xocrange.event_store import Store
from xocrange.ui_setup import private_json


def run(*args):
    return subprocess.check_output(args,text=True).strip()


def volumes(project):
    names=run('docker','volume','ls','--filter','label=com.docker.compose.project='+project,'--format','{{.Name}}').splitlines()
    return {v['Name']:{k:v.get(k) for k in ('CreatedAt','Mountpoint','Driver')}
        for v in json.loads(run('docker','volume','inspect',*names))} if names else {}


def active(unit):
    return subprocess.run(['systemctl','is-active','--quiet',unit]).returncode==0


def audit_lines():
    return [shlex.split(line) for line in run('auditctl','-l').splitlines()]


def check_excluded(before,directory):
    last=private_json(STATE/'last-install.json');store=Store(STATE/'siem')
    running=set(run('docker','ps','--filter','label=com.docker.compose.project='+before['project'],
        '--format','{{.Label "com.docker.compose.service"}}').splitlines())
    lifecycle=private_json(directory/'lifecycle.json')
    proof=anchor_integrity(store,lifecycle['anchors'])
    rules=audit_lines()
    current_volumes=volumes(before['project'])
    checks={'installation_succeeded':last.get('status')=='installed',
        'siem_unselected':not {'siem','siem-ui'} & set(last.get('selected',[])),
        'siem_containers_absent':not {'siem','indexer','dashboard'} & running,
        'management_gateway_kept':'ingress' in running and 'management' in last.get('selected',[]),
        'common_accounts_keys_policies_kept':common_identity(before['project'])==before['common_identity'],
        'security_path_running':{'platform','fw','ips','web','lab-target','lab-client'}<=running,
        'collection_services_stopped':all(not active(unit) for unit in ('xocrange-collector','xocrange-osquery','sysmon')),
        'collection_services_disabled':all(run('systemctl','show',unit,'--property=UnitFileState','--value')=='disabled'
            for unit in ('xocrange-collector','xocrange-osquery','sysmon')),
        'os_auditd_kept':active('auditd'),
        'owned_audit_rules_removed':not any(key in row for key in ('xoc_config','xoc_probe','xoc_privilege') for row in rules),
        'owned_persistent_rules_removed':not Path('/etc/audit/rules.d/70-xocrange.rules').exists(),
        'unrelated_audit_watch_kept':before['watch'] in rules,
        'all_existing_volumes_kept':all(current_volumes.get(k)==v for k,v in before['volumes'].items()),
        'credentials_and_cas_kept':all(fingerprint(path)==digest for path,digest in before['identity'].items()),
        'raw_and_c1_anchors_kept':proof['raw_matches']==proof['event_matches']==24}
    import importlib.util
    spec=importlib.util.spec_from_file_location('core_probe',Path(last['release'])/'scripts/verify-platform.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    secret=private_json(STATE/'platform/credentials.json');session=module.Session(secret['public_host'])
    code,body,_,_=session.login('admin',secret.get('admin_password',secret['bootstrap_password']))
    checks['core_login_without_siem']=code==200 and body.get('role')=='admin'
    checks['siem_link_disabled']=body.get('siem_available') is False
    checks['core_policies_read_without_siem']=session.request('/core/api/devices')[0]==200
    checks['core_logout_without_siem']=session.request('/core/api/logout',{})[0]==200
    counts={table:store.db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0]
        for table in ('records','events','wazuh_alerts','native_inputs')}
    count_path=directory/'excluded-counts.json'
    if count_path.exists():checks['excluded_reinstall_did_not_change_evidence_counts']=counts==private_json(count_path)
    else:save_new(count_path,counts)
    return {'status':'passed' if all(checks.values()) else 'failed','checks':checks,'evidence_counts':counts,'install_log':last.get('log')}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['checkpoint','excluded','restored','cleanup'])
    parser.add_argument('--run',required=True)
    parser.add_argument('--isolated-vm',action='store_true')
    args=parser.parse_args()
    if not args.isolated_vm or os.geteuid()!=0:parser.error('Root and --isolated-vm are required')
    if not re.fullmatch('[a-z0-9][a-z0-9-]{0,40}',args.run):parser.error('Use a short alphanumeric run ID')
    directory=STATE/'validation'/'siem-selection'/args.run
    with installation_lock():
        private_directory(directory);path=directory/'checkpoint.json'
        if args.action=='checkpoint':
            if path.exists() or (directory/'lifecycle.json').exists():raise RuntimeError('Choose a new run ID')
            installed=Installed(True);installed.checkpoint(directory/'lifecycle.json')
            key='xocval_'+uuid.uuid4().hex[:16];target=directory/'host-audit-watch';target.touch(mode=0o600)
            watch=['-w',str(target),'-p','wa','-k',key]
            rule_path=Path('/etc/audit/rules.d')/(key+'.rules')
            rule_path.write_text(shlex.join(watch)+'\n');rule_path.chmod(0o600)
            subprocess.run(['auditctl',*watch],check=True,capture_output=True)
            identities=[STATE/'ui/credentials.json',STATE/'ui/ca.pem',STATE/'manager/credentials.json',STATE/'manager/ca.pem']
            save_new(path,{'release':str(installed.root),'project':installed.project,'watch':watch,'rule_path':str(rule_path),
                'rule_sha256':fingerprint(rule_path),'volumes':volumes(installed.project),
                'common_identity':common_identity(installed.project),
                'identity':{str(p):fingerprint(p) for p in identities}})
            result={'status':'checkpoint-created','evidence_anchors':24,'native_alert_anchors':24,'raw_source_receipts':8}
        else:
            before=private_json(path)
            if args.action=='excluded':result=check_excluded(before,directory)
            elif args.action=='restored':
                installed=Installed(True);result=installed.verify(directory/'lifecycle.json','reinstall',300)
                current_volumes=volumes(before['project'])
                result['checks'].update(unrelated_audit_watch_kept=before['watch'] in audit_lines(),
                    owned_audit_rules_restored=all(any(key in row for row in audit_lines()) for key in ('xoc_config','xoc_probe','xoc_privilege')),
                    all_existing_volumes_kept=all(current_volumes.get(k)==v for k,v in before['volumes'].items()))
                result['status']='passed' if all(result['checks'].values()) else 'failed'
            else:
                installed=Installed(True);result=installed.cleanup(directory/'lifecycle.json')
                rule_path=Path(before['rule_path'])
                if fingerprint(rule_path)!=before['rule_sha256'] or before['watch'] not in audit_lines():
                    raise RuntimeError('Temporary audit watch changed; refusing cleanup')
                subprocess.run(['auditctl','-W',*before['watch'][1:]],check=True,capture_output=True)
                rule_path.unlink();Path(before['watch'][1]).unlink()
        report=directory/(args.action+'.'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')+'.json')
        save_new(report,result);print(json.dumps(result,indent=2))
        return 0 if result['status']!='failed' else 2


if __name__=='__main__':raise SystemExit(main())
