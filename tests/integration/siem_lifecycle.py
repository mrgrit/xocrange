#!/usr/bin/env python3
"""Explicit acceptance for the installed SIEM on its dedicated VM.

Runs with the installed release's Python. A checkpoint never overwrites another
run. No action reinstalls, reboots, purges volumes or resets credentials.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import time
import uuid

from xocrange.documents import canonical
from xocrange.errors import XocError
from xocrange.event_store import Store, now
from xocrange.events import SOURCES
from xocrange.indexer import Client
from xocrange.lab import Docker, checked_plan, host_check
from xocrange.native_alerts import document as alert_document
from xocrange.ui_setup import private_json

STATE=Path('/var/lib/xocrange')


def fingerprint(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def common_identity(project):
    """Hash stable auth/policy state; omit sessions and append-only audit rows."""
    import sqlite3
    credentials=private_json(STATE/'platform/credentials.json')
    volume=json.loads(subprocess.check_output(['docker','volume','inspect',project+'_platform-data'],text=True))[0]
    database=Path(volume['Mountpoint'])/'control.sqlite3'
    db=sqlite3.connect(database.as_uri()+'?mode=ro',uri=True)
    try:
        value={'keys':{k:credentials[k] for k in ('secret_key','bootstrap_password')},
            'users':db.execute('SELECT u.username,u.password,u.is_active,p.role,p.generation,p.must_change_password FROM auth_user u JOIN control_profile p ON p.user_id=u.id ORDER BY u.username').fetchall(),
            'devices':db.execute('SELECT device,write_enabled,version FROM control_devicepolicy ORDER BY device').fetchall()}
        return hashlib.sha256(canonical(value)).hexdigest()
    finally:db.close()


@contextmanager
def installation_lock(path=Path('/run/lock/xocrange-install.lock')):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            raise XocError('installation_busy','An installation or lifecycle verification is already running.')
        yield
    finally:os.close(fd)


def private_directory(path):
    if any(p.is_symlink() for p in (path,*path.parents)):
        raise XocError('unsafe_checkpoint','Validation state cannot traverse symlinks.')
    path.mkdir(parents=True,exist_ok=True,mode=0o700)
    if path.stat().st_uid!=os.geteuid() or path.stat().st_mode & 0o077:
        raise XocError('unsafe_checkpoint','Validation state must be private and locally owned.')


def save_new(path,data):
    # O_EXCL also rejects an existing symlink; never replace another run's proof.
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as stream:
        json.dump(data,stream,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())


def capture_anchors(store,per_source=3):
    anchors=[]
    for source in SOURCES:
        candidates=store.db.execute('''SELECT e.id,e.ref,e.producer,e.observed,e.event,r.sha256,r.raw
          FROM events e JOIN records r ON r.ref=e.ref
          WHERE e.producer=? AND e.confirmed IS NOT NULL AND e.indexed IS NOT NULL
          ORDER BY e.observed DESC,e.id''',(source,))
        rows=[];references=set()
        for row in candidates:
            # A ModSecurity transaction can produce several C1 children. Keep
            # three distinct raw records, not three children of one record.
            if row['ref'] in references:continue
            rows.append(row);references.add(row['ref'])
            if len(rows)==per_source:break
        candidates.close()
        if len(rows)!=per_source:
            raise XocError('insufficient_evidence','Every source needs confirmed, indexed evidence before a checkpoint.')
        for row in rows:
            if hashlib.sha256(row['raw']).hexdigest()!=row['sha256']:
                raise XocError('evidence_corrupt','Stored raw evidence does not match its hash.')
            anchors.append({k:row[k] for k in ('id','ref','producer','observed','sha256')} |
                           {'event_sha256':hashlib.sha256(canonical(json.loads(row['event']))).hexdigest()})
    return anchors


def anchor_integrity(store,anchors):
    raw_count=event_count=indexed_count=0
    for anchor in anchors:
        row=store.db.execute('''SELECT e.ref,e.producer,e.observed,e.event,e.indexed,r.raw,r.sha256
          FROM events e JOIN records r ON r.ref=e.ref WHERE e.id=?''',(anchor['id'],)).fetchone()
        if row is None:continue
        raw_count+=row['ref']==anchor['ref'] and row['sha256']==anchor['sha256'] and hashlib.sha256(row['raw']).hexdigest()==anchor['sha256']
        event_count+=row['producer']==anchor['producer'] and row['observed']==anchor['observed'] and hashlib.sha256(canonical(json.loads(row['event']))).hexdigest()==anchor['event_sha256']
        indexed_count+=row['indexed'] is not None
    return {'total':len(anchors),'raw_matches':raw_count,'event_matches':event_count,'indexed':indexed_count}


def indexed_integrity(client,anchors):
    docs=[{'_index':'xoc-events-'+a['observed'][:10].replace('-','.'),'_id':a['id']} for a in anchors]
    status,reply=client.request('POST','/_mget',{'docs':docs})
    found=reply.get('docs',[])
    if status!=200 or len(found)!=len(anchors):return False
    for anchor,item in zip(anchors,found):
        source=dict(item.get('_source',{}));source.pop('wazuh',None)
        if not item.get('found') or item.get('_id')!=anchor['id'] or hashlib.sha256(canonical(source)).hexdigest()!=anchor['event_sha256']:
            return False
    status,reply=client.request('POST','/xoc-events-*/_search',{'size':0,'track_total_hits':True,'query':{'ids':{'values':[a['id'] for a in anchors]}}})
    return status==200 and reply.get('hits',{}).get('total',{}).get('value')==len(anchors)


def wait_for(predicate,seconds,message):
    deadline=time.monotonic()+seconds
    while True:
        if predicate():return
        if time.monotonic()>=deadline:raise XocError('validation_timeout',message)
        time.sleep(2)


def fresh_check(command,stage,timeout):
    try:
        subprocess.run(command,check=True,timeout=timeout,stdout=subprocess.DEVNULL)
    except subprocess.SubprocessError as error:
        raise XocError(stage,'A fresh live acceptance check failed; inspect the installed service logs.') from error


def stopped_indexer_probe(engine,probe):
    # Even an exception in the probe must attempt to restore the same service.
    try:
        engine.run(['stop','indexer'],compose=True)
        return probe()
    finally:
        engine.run(['start','indexer'],compose=True)


class Installed:
    def __init__(self,isolated_vm):
        if not isolated_vm or os.geteuid()!=0:
            raise XocError('isolated_vm_required','Run as root with --isolated-vm on the dedicated test VM.')
        if not (STATE/'installer-owned').is_file():
            raise XocError('not_installed','The xOC installer does not own this host.')
        self.install=private_json(STATE/'last-install.json')
        if self.install.get('status')!='installed' or 'siem-ui' not in self.install.get('selected',[]):
            raise XocError('not_installed','A successful SIEM UI installation is required.')
        # ExecStartPost performs its own disruptive IPS acceptance. Never run
        # another lab verification concurrently while the unit is activating.
        wait_for(lambda:subprocess.run(['systemctl','is-active','--quiet','xocrange-core']).returncode==0,
                 180,'The boot acceptance service did not become active.')
        self.root=Path(self.install['release'])
        if self.root.parent!=Path('/opt/xocrange/releases') or not re.fullmatch('[a-f0-9]{64}',self.root.name) or self.root.is_symlink():
            raise XocError('untrusted_release','Unexpected installed release location.')
        directory,plan=checked_plan(self.root,self.install['plan'])
        self.project=plan['compose']['name'];self.engine=Docker(directory/'compose.yaml',self.project)
        inspection=host_check(self.engine,self.project)
        if inspection['status']!='ready':
            raise XocError('unsafe_host','Dedicated VM prerequisites failed; no validation changes were made.')
        self.client=Client(self.engine,self.project,user='admin')
        self.store=Store(STATE/'siem')
        self.python=Path('/opt/xocrange/venvs')/self.root.name/'bin/python'

    def identity(self):
        # Hashes remain in root-only state; public reports contain booleans only.
        private_json(STATE/'ui/credentials.json')
        result={'credentials_sha256':fingerprint(STATE/'ui/credentials.json'),'ca_sha256':fingerprint(STATE/'ui/ca.pem')}
        result['common_security_sha256']=common_identity(self.project)
        if (self.root/'components/siem/bootstrap.py').is_file():
            result.update(manager_credentials_sha256=fingerprint(STATE/'manager/credentials.json'),manager_ca_sha256=fingerprint(STATE/'manager/ca.pem'))
        return result

    def manager(self):
        from xocrange.manager_api import ManagerClient
        client=ManagerClient(self.engine,self.project)
        return client,client.authenticate()

    def native_checkpoint(self):
        anchors=[]
        for producer in SOURCES:
            rows=self.store.db.execute('''SELECT n.id,n.observed,n.raw,n.sha256,n.document,n.annotation FROM wazuh_alerts n JOIN events e ON e.id=n.event_id
              WHERE e.producer=? AND n.indexed IS NOT NULL ORDER BY n.observed DESC LIMIT 3''',(producer,)).fetchall()
            if len(rows)!=3:raise XocError('native_evidence_missing','Need three native alerts from every source.')
            for row in rows:
                if hashlib.sha256(row['raw']).hexdigest()!=row['sha256']:raise XocError('evidence_corrupt','Native evidence is corrupt.')
                anchors.append({'id':row['id'],'observed':row['observed'],'sha256':row['sha256'],'document_sha256':hashlib.sha256(canonical(json.loads(alert_document(row)))).hexdigest()})
        inputs=[]
        if self.store.cursor('native-input-enabled'):
            for source in SOURCES:
                row=self.store.db.execute('''SELECT id,ref,source,frame_sha256,confirmed,decoder FROM native_inputs
                    WHERE source=? AND confirmed IS NOT NULL AND error IS NULL AND decoder!='sensor-diagnostic'
                    ORDER BY observed DESC LIMIT 1''',(source,)).fetchone()
                if row is None:raise XocError('native_input_missing','Every raw source needs a processing receipt.')
                inputs.append(dict(row))
        client,token=self.manager();username='xoc-lifecycle-'+uuid.uuid4().hex[:12]
        code,data=client.request('POST','/security/users',{'username':username,'password':'Xoc1!'+secrets.token_urlsafe(24)},token=token)
        items=data.get('data',{}).get('affected_items',[])
        if code not in (200,201) or len(items)!=1:raise XocError('native_checkpoint_user','Cannot create the private RBAC persistence probe.')
        return {'anchors':anchors,'user':items[0],'raw_inputs':inputs}

    def remove_native_user(self,native):
        user=native['user']
        if not re.fullmatch('xoc-lifecycle-[a-f0-9]{12}',user.get('username','')) or type(user.get('id')) is not int:
            raise XocError('native_checkpoint_user','Unexpected lifecycle API user.')
        client,token=self.manager()
        code,data=client.request('GET','/security/users?user_ids='+str(user['id']),token=token)
        items=data.get('data',{}).get('affected_items',[])
        if not items:return
        if code!=200 or len(items)!=1 or items[0]['username']!=user['username']:
            raise XocError('native_checkpoint_user','Refusing to delete an unrelated API user.')
        code,data=client.request('DELETE','/security/users?user_ids='+str(user['id']),token=token)
        if code!=200 or data.get('data',{}).get('total_affected_items')!=1:raise XocError('native_cleanup','Cannot delete the owned API probe.')

    def verify_native(self,native):
        anchors=native['anchors'];matches=0
        for anchor in anchors:
            row=self.store.db.execute('SELECT raw,sha256,document,annotation,indexed FROM wazuh_alerts WHERE id=?',(anchor['id'],)).fetchone()
            matches+=bool(row and row['indexed'] and hashlib.sha256(row['raw']).hexdigest()==anchor['sha256'] and hashlib.sha256(canonical(json.loads(alert_document(row)))).hexdigest()==anchor['document_sha256'])
        docs=[{'_index':'wazuh-alerts-4.x-'+a['observed'][:10].replace('-','.'),'_id':a['id']} for a in anchors]
        code,data=self.client.request('POST','/_mget',{'docs':docs})
        found=data.get('docs',[])
        indexed=code==200 and len(found)==len(anchors) and all(row.get('found') and row.get('_id')==a['id'] and hashlib.sha256(canonical(row.get('_source',{}))).hexdigest()==a['document_sha256'] for a,row in zip(anchors,found))
        code,data=self.client.request('POST','/wazuh-alerts-4.x-*/_search',{'size':0,'track_total_hits':True,'query':{'ids':{'values':[a['id'] for a in anchors]}}})
        unique=code==200 and data.get('hits',{}).get('total',{}).get('value')==len(anchors)
        client,token=self.manager();code,data=client.request('GET','/security/users?user_ids='+str(native['user']['id']),token=token)
        checks={'native_alerts_preserved':matches==len(anchors)==24,'native_index_documents_preserved':indexed and unique,'custom_manager_api_user_preserved':code==200 and data.get('data',{}).get('affected_items')==[native['user']]}
        if native.get('raw_inputs'):
            receipts=[]
            for anchor in native['raw_inputs']:
                row=self.store.db.execute('SELECT id,ref,source,frame_sha256,confirmed,decoder FROM native_inputs WHERE id=?',(anchor['id'],)).fetchone()
                receipts.append(row is not None and dict(row)==anchor)
            checks['eight_raw_processing_receipts_preserved']=len(receipts)==8 and all(receipts)
        return checks

    def checkpoint(self,path):
        if path.exists() or path.is_symlink():
            raise XocError('checkpoint_exists','Choose a new run ID; checkpoints cannot be overwritten.')
        anchors=capture_anchors(self.store)
        # Bulk acknowledgment and realtime _mget precede the five-second search
        # refresh. Wait on these fixed anchors, without selecting newer ones.
        wait_for(lambda:indexed_integrity(self.client,anchors),30,
                 'Checkpoint evidence must also be searchable without duplicates.')
        object_id='xoc-lifecycle-'+uuid.uuid4().hex
        attributes={'title':'xOC lifecycle acceptance '+object_id,'description':'Temporary preservation probe','columns':['producer','event.action'],'sort':[['timestamp','desc']],'kibanaSavedObjectMeta':{'searchSourceJSON':'{"query":{"query":"","language":"kuery"},"filter":[]}'}}
        route='/siem/api/saved_objects/search/'+object_id
        code,obj=self.client.request('POST',route,{'attributes':attributes},service='dashboard')
        if code!=200:raise XocError('checkpoint_object','Cannot create the preservation probe.')
        native=None
        try:
            code,obj=self.client.request('GET',route,service='dashboard')
            if code!=200:raise XocError('checkpoint_object','Cannot read the preservation probe.')
            if (self.root/'components/siem/bootstrap.py').is_file():native=self.native_checkpoint()
            save_new(path,{'schema':'xoc.siem.lifecycle/1','created_at':now(),'release':self.root.name,'project':self.project,'install_run':self.install['log'],'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),**self.identity(),'anchors':anchors,'object_id':object_id,'attributes':obj['attributes'],'native':native})
        except BaseException:
            if native:self.remove_native_user(native)
            self.client.request('DELETE',route,service='dashboard');raise
        return {'status':'checkpoint-created','evidence_anchors':len(anchors),'release':self.root.name}

    def validate_checkpoint(self,path):
        data=private_json(path)
        if data.get('schema')!='xoc.siem.lifecycle/1' or data.get('project')!=self.project or data.get('release')!=self.root.name:
            raise XocError('checkpoint_mismatch','The checkpoint belongs to a different project or source release.')
        if not re.fullmatch('xoc-lifecycle-[a-f0-9]{32}',data.get('object_id','')):
            raise XocError('checkpoint_mismatch','Unexpected preservation object identifier.')
        if len(data.get('anchors',[]))!=3*len(SOURCES):
            raise XocError('checkpoint_mismatch','Expected three evidence anchors from each source.')
        return data

    def verify(self,path,after,timeout):
        before=self.validate_checkpoint(path)
        if after=='reinstall' and before.get('install_run')==self.install['log']:
            raise XocError('reinstall_not_observed','Installation run is unchanged; this is not a reinstall verification.')
        boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        if after=='reboot' and before['boot_id']==boot:
            raise XocError('reboot_not_observed','Boot ID is unchanged; this is not a reboot verification.')
        # Run fresh checks; a report left by an earlier install cannot prove this run.
        fresh_check([str(self.python),'-m','xocrange','--root',str(self.root),'lab','verify','--plan',self.install['plan'],'--isolated-vm'],'security_path_regression',240)
        for name in ('verify-siem.py','verify-siem-ui.py'):
            fresh_check([str(self.python),str(self.root/'scripts'/name),str(self.root),self.install['plan']],name.removesuffix('.py').replace('-','_')+'_regression',600)
        wait_for(lambda:self.store.status()['status']=='ready',timeout,'Collector or indexing backlog did not recover.')
        integrity=anchor_integrity(self.store,before['anchors'])
        identity=self.identity()
        code,obj=self.client.request('GET','/siem/api/saved_objects/search/'+before['object_id'],service='dashboard')
        checks={'credentials_preserved':identity['credentials_sha256']==before['credentials_sha256'],'ca_preserved':identity['ca_sha256']==before['ca_sha256'],'saved_object_preserved':code==200 and obj.get('attributes')==before['attributes'],'raw_evidence_preserved':integrity['raw_matches']==integrity['total'],'c1_events_preserved':integrity['event_matches']==integrity['total'],'all_anchors_acknowledged':integrity['indexed']==integrity['total'],'index_documents_preserved_without_duplicates':indexed_integrity(self.client,before['anchors']),'core_active':subprocess.run(['systemctl','is-active','--quiet','xocrange-core']).returncode==0,'collector_active':subprocess.run(['systemctl','is-active','--quiet','xocrange-collector']).returncode==0}
        checks['common_accounts_keys_policies_preserved']=identity['common_security_sha256']==before.get('common_security_sha256')
        if after=='reboot':checks['boot_id_changed']=before['boot_id']!=boot
        if before.get('native'):
            checks.update(self.verify_native(before['native']))
            checks['manager_credentials_preserved']=identity['manager_credentials_sha256']==before['manager_credentials_sha256']
            checks['manager_ca_preserved']=identity['manager_ca_sha256']==before['manager_ca_sha256']
        return {'status':'passed' if all(checks.values()) else 'failed','after':after,'release':self.root.name,'checks':checks,'evidence':integrity,'fresh_security_path_checks':15,'fresh_source_checks':len(SOURCES),'fresh_https_checks':len(private_json(STATE/'siem-ui-acceptance.json')['checks'])}

    def outage(self,timeout):
        code,health=self.client.request('GET','/_cluster/health')
        if code!=200 or health.get('status') not in ('green','yellow'):
            raise XocError('indexer_not_ready','Start outage verification from a healthy Indexer.')
        cutoff=now();queued=[];native_queued=[];raw_queued=[]
        native=(self.root/'components/siem/bootstrap.py').is_file()
        raw=bool(self.store.cursor('native-input-enabled'))
        def probe():
            self.engine.run(['exec','-T','lab-client','python','-B','/app/probe.py'],compose=True)
            subprocess.run(['/usr/bin/true'],check=True)
            def observed():
                queued[:]=self.store.db.execute('SELECT id,observed FROM events WHERE observed>=? AND confirmed IS NOT NULL AND indexed IS NULL ORDER BY observed LIMIT 100',(cutoff,)).fetchall()
                health=self.store.db.execute("SELECT status FROM health WHERE source='indexer'").fetchone()
                if native:
                    native_queued[:]=self.store.db.execute('SELECT id FROM wazuh_alerts WHERE observed>=? AND indexed IS NULL ORDER BY observed LIMIT 100',(cutoff,)).fetchall()
                if raw:
                    raw_queued[:]=self.store.db.execute("SELECT id FROM wazuh_alerts WHERE observed>=? AND indexed IS NULL AND COALESCE(json_extract(annotation,'$.analysis_route'),json_extract(NULLIF(document,''),'$.xoc.analysis_route'))='raw' ORDER BY observed LIMIT 100",(cutoff,)).fetchall()
                return len(queued)==100 and health is not None and health[0]!='ready' and (not native or len(native_queued)==100) and (not raw or len(raw_queued)==100)
            wait_for(observed,min(timeout,90),'Did not observe 100 Wazuh-confirmed queued events and an Indexer failure.')
        stopped_indexer_probe(self.engine,probe)
        ids=[r['id'] for r in queued]
        wait_for(lambda:all(self.store.db.execute('SELECT indexed FROM events WHERE id=?',(i,)).fetchone()[0] for i in ids),timeout,'Queued events did not recover after Indexer restart.')
        def searchable():
            code,data=self.client.request('POST','/xoc-events-*/_search',{'size':0,'track_total_hits':True,'query':{'ids':{'values':ids}}})
            return code==200 and data.get('hits',{}).get('total',{}).get('value')==len(ids)
        wait_for(searchable,30,'Recovered queue is missing or duplicated in search.')
        result={'status':'passed','wazuh_confirmation_continued':True,'indexer_failure_reported':True,'queued_events_checked':len(ids),'recovered_unique_documents':len(ids)}
        if native:
            native_ids=[r['id'] for r in native_queued]
            wait_for(lambda:all(self.store.db.execute('SELECT indexed FROM wazuh_alerts WHERE id=?',(i,)).fetchone()[0] for i in native_ids),timeout,'Native alert queue did not recover.')
            def native_searchable():
                code,data=self.client.request('POST','/wazuh-alerts-4.x-*/_search',{'size':0,'track_total_hits':True,'query':{'ids':{'values':native_ids}}})
                return code==200 and data.get('hits',{}).get('total',{}).get('value')==len(native_ids)
            wait_for(native_searchable,30,'Native alert recovery is missing or duplicated.')
            result['native_alerts_recovered_without_duplicates']=len(native_ids)
        if raw:
            raw_ids=[r['id'] for r in raw_queued]
            wait_for(lambda:all(self.store.db.execute('SELECT indexed FROM wazuh_alerts WHERE id=?',(i,)).fetchone()[0] for i in raw_ids),timeout,'Raw-source alert queue did not recover.')
            def raw_searchable():
                code,data=self.client.request('POST','/wazuh-alerts-4.x-*/_search',{'size':0,'track_total_hits':True,'query':{'ids':{'values':raw_ids}}})
                return code==200 and data.get('hits',{}).get('total',{}).get('value')==100
            wait_for(raw_searchable,30,'Raw-source alert recovery is missing or duplicated.')
            result['raw_source_alerts_recovered_without_duplicates']=100
        return result

    def cleanup(self,path):
        before=self.validate_checkpoint(path)
        if before.get('native'):self.remove_native_user(before['native'])
        code,_=self.client.request('DELETE','/siem/api/saved_objects/search/'+before['object_id'],service='dashboard')
        if code not in (200,404):raise XocError('cleanup_failed','Could not remove the owned preservation probe.')
        return {'status':'cleaned','retained':['checkpoint','reports','all_evidence','all_volumes']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['checkpoint','verify','outage','cleanup'])
    parser.add_argument('--run',required=True)
    parser.add_argument('--isolated-vm',action='store_true')
    parser.add_argument('--after',choices=['reinstall','reboot'])
    parser.add_argument('--timeout',type=int,default=240)
    args=parser.parse_args()
    if not re.fullmatch('[a-z0-9][a-z0-9-]{0,63}',args.run) or not 10<=args.timeout<=900:
        parser.error('Use a simple run ID and a timeout from 10 to 900 seconds.')
    if args.action=='verify' and not args.after:parser.error('verify requires --after')
    report=None
    try:
        if not args.isolated_vm or os.geteuid()!=0:
            raise XocError('isolated_vm_required','Run as root with --isolated-vm on the dedicated test VM.')
        with installation_lock():
            installed=Installed(args.isolated_vm)
            directory=STATE/'validation'/'siem-lifecycle';private_directory(directory)
            checkpoint=directory/(args.run+'.checkpoint.json')
            # Timestamped reports survive failures and never replace a previous result.
            report=directory/(args.run+'.'+args.action+'.'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')+'.json')
            if args.action=='checkpoint':result=installed.checkpoint(checkpoint)
            elif args.action=='verify':result=installed.verify(checkpoint,args.after,args.timeout)
            elif args.action=='outage':result=installed.outage(args.timeout)
            else:result=installed.cleanup(checkpoint)
    except (XocError,OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as error:
        result={'status':'failed','error':getattr(error,'code','validation_failed')}
    except KeyboardInterrupt:
        result={'status':'failed','error':'interrupted'}
    if report is not None:save_new(report,result)
    print(json.dumps(result,indent=2))
    return 2 if result['status']=='failed' else 0


if __name__=='__main__':raise SystemExit(main())
