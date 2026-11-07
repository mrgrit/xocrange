import importlib.util
import json
from pathlib import Path

import pytest

from xocrange.documents import canonical
from xocrange.errors import XocError
from xocrange.event_store import Store
from xocrange.events import SOURCES

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('siem_lifecycle',ROOT/'tests/integration/siem_lifecycle.py')
lifecycle=importlib.util.module_from_spec(spec);spec.loader.exec_module(lifecycle)
FILES=dict(zip(SOURCES,('nftables-drop.log','suricata-alert.json','modsecurity-audit.json','osquery-results.json','sysmon-process.xml','auditd-exec.log','apache-access.json','apache-error.log')))


@pytest.fixture
def store(tmp_path):
    value=Store(tmp_path/'evidence')
    with value.transaction():
        for source,filename in FILES.items():
            for offset in range(3):
                value.ingest(source,'trusted-'+source,str(offset),(ROOT/'tests/fixtures/events'/filename).read_bytes(),observed='2026-11-07T13:00:00Z')
        value.db.execute("UPDATE events SET confirmed='2026-11-07T13:00:01Z',indexed='2026-11-07T13:00:02Z',rule_id='110020'")
    yield value
    value.db.close()


def test_checkpoint_covers_every_source_and_survives_database_reopen(store):
    anchors=lifecycle.capture_anchors(store)
    assert len(anchors)==24 and {a['producer'] for a in anchors}==set(SOURCES)
    assert len({a['ref'] for a in anchors})==24
    path=store.directory
    reopened=Store(path)
    assert lifecycle.anchor_integrity(reopened,anchors)=={'total':24,'raw_matches':24,'event_matches':24,'indexed':24}
    reopened.db.close()


def test_raw_and_normalized_evidence_tampering_are_detected_separately(store):
    anchors=lifecycle.capture_anchors(store);a=anchors[0]
    with store.transaction():store.db.execute('UPDATE records SET raw=? WHERE ref=?',(b'changed',a['ref']))
    proof=lifecycle.anchor_integrity(store,anchors)
    assert proof['raw_matches']<24 and proof['event_matches']==24
    with store.transaction():store.db.execute("UPDATE events SET event=json_set(event,'$.event.outcome','failure') WHERE id=?",(a['id'],))
    assert lifecycle.anchor_integrity(store,anchors)['event_matches']<24


def test_checkpoint_rejects_missing_or_unacknowledged_source(store):
    with store.transaction():store.db.execute("UPDATE events SET indexed=NULL WHERE producer='auditd'")
    with pytest.raises(XocError,match='Every source'):lifecycle.capture_anchors(store)


def test_checkpoint_waits_for_search_refresh_of_the_same_anchors(store,tmp_path,monkeypatch):
    installed=lifecycle.Installed.__new__(lifecycle.Installed)
    installed.store=store;installed.root=tmp_path/'release';installed.project='owned'
    installed.install={'log':'new-install'};installed.identity=lambda:{}
    class Client:
        def request(self,*args,**kwargs):return 200,{'attributes':{'title':'probe'}}
    installed.client=Client();seen=[];sleeps=[]
    def searchable(client,anchors):
        seen.append([a['id'] for a in anchors]);return len(seen)>=3
    monkeypatch.setattr(lifecycle,'indexed_integrity',searchable)
    monkeypatch.setattr(lifecycle.time,'sleep',sleeps.append)
    assert installed.checkpoint(tmp_path/'checkpoint.json')['status']=='checkpoint-created'
    assert len(seen)==3 and seen[0]==seen[1]==seen[2] and sleeps==[2,2]


@pytest.mark.parametrize('change',['none','duplicate','wrong-content','missing'])
def test_index_verification_requires_matching_c1_and_unique_documents(store,change):
    anchors=lifecycle.capture_anchors(store)
    class Client:
        def request(self,method,path,body):
            if path=='/_mget':
                docs=[{'_id':a['id'],'found':True,'_source':json.loads(store.db.execute('SELECT event FROM events WHERE id=?',(a['id'],)).fetchone()[0])|{'wazuh':{'rule_id':'110020'}}} for a in anchors]
                if change=='wrong-content':docs[0]['_source']['producer']='wrong'
                if change=='missing':docs[0]['found']=False
                return 200,{'docs':docs}
            return 200,{'hits':{'total':{'value':len(anchors)+(change=='duplicate')}}}
    assert lifecycle.indexed_integrity(Client(),anchors)==(change=='none')


def test_checkpoint_never_overwrites_or_follows_symlink(tmp_path):
    path=tmp_path/'checkpoint.json';lifecycle.save_new(path,{'original':True})
    assert path.stat().st_mode & 0o777==0o600
    with pytest.raises(FileExistsError):lifecycle.save_new(path,{'original':False})
    link=tmp_path/'link';link.symlink_to(path)
    with pytest.raises(FileExistsError):lifecycle.save_new(link,{})
    assert json.loads(path.read_text())=={'original':True}


def test_checkpoint_directory_refuses_shared_or_redirected_path(tmp_path):
    shared=tmp_path/'shared';shared.mkdir(mode=0o755)
    with pytest.raises(XocError):lifecycle.private_directory(shared)
    link=tmp_path/'link';link.symlink_to(tmp_path)
    with pytest.raises(XocError):lifecycle.private_directory(link/'private')


@pytest.mark.parametrize('failure',['probe','stop'])
def test_outage_always_attempts_restart_when_probe_or_stop_fails(failure):
    calls=[]
    class Engine:
        def run(self,args,**kwargs):
            calls.append(args)
            if failure=='stop' and args[0]=='stop':raise XocError('stop_failed','stop failed')
    def probe():raise XocError('probe_failed','probe failed')
    with pytest.raises(XocError):lifecycle.stopped_indexer_probe(Engine(),probe)
    assert calls==[['stop','indexer'],['start','indexer']]


def test_checkpoint_from_other_release_cannot_be_verified_or_cleaned(tmp_path):
    path=tmp_path/'checkpoint.json'
    lifecycle.save_new(path,{'schema':'xoc.siem.lifecycle/1','project':'owned','release':'old','object_id':'xoc-lifecycle-'+'a'*32})
    installed=lifecycle.Installed.__new__(lifecycle.Installed);installed.project='owned';installed.root=Path('/release/new')
    with pytest.raises(XocError,match='different project or source'):installed.validate_checkpoint(path)


def test_reboot_requires_boot_id_change_before_live_commands(tmp_path,monkeypatch):
    installed=lifecycle.Installed.__new__(lifecycle.Installed)
    monkeypatch.setattr(installed,'validate_checkpoint',lambda path:{'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()})
    with pytest.raises(XocError,match='Boot ID is unchanged'):installed.verify(tmp_path/'unused','reboot',10)


def test_live_actions_require_explicit_isolated_vm_selection():
    with pytest.raises(XocError,match='--isolated-vm'):lifecycle.Installed(False)


def test_native_checkpoint_covers_eight_sources_and_creates_only_an_unprivileged_probe(store):
    from xocrange.native_alerts import accept
    with store.transaction():
        for i,row in enumerate(store.db.execute('SELECT event FROM events').fetchall()):
            accept(store,canonical({'id':str(i),'timestamp':'2026-11-07T13:00:00Z','manager':{'name':'xoc'},'data':json.loads(row[0]),'rule':{'id':'110020'}}))
        store.db.execute("UPDATE wazuh_alerts SET indexed='2026-11-07T13:01:00Z'")
    calls=[]
    class Manager:
        def request(self,method,path,body,**kwargs):
            calls.append((method,path,body))
            return 200,{'data':{'affected_items':[{'id':100,'username':body['username'],'roles':[],'allow_run_as':False}]}}
    installed=lifecycle.Installed.__new__(lifecycle.Installed);installed.store=store;installed.manager=lambda:(Manager(),'private-token')
    proof=installed.native_checkpoint()
    assert len(proof['anchors'])==24 and len({a['id'] for a in proof['anchors']})==24
    assert proof['user']['roles']==[] and not proof['user']['allow_run_as']
    assert len(calls)==1 and calls[0][:2]==('POST','/security/users') and set(calls[0][2])=={'username','password'}
    assert 'password' not in proof['user']


def test_native_cleanup_never_deletes_a_different_api_user():
    calls=[]
    class Manager:
        def request(self,method,path,**kwargs):
            calls.append(method)
            return 200,{'data':{'affected_items':[{'id':100,'username':'someone-else'}]}}
    installed=lifecycle.Installed.__new__(lifecycle.Installed);installed.manager=lambda:(Manager(),'private-token')
    with pytest.raises(XocError,match='unrelated'):
        installed.remove_native_user({'user':{'id':100,'username':'xoc-lifecycle-'+'a'*12}})
    assert calls==['GET']


def test_reinstall_requires_a_new_installer_run(tmp_path,monkeypatch):
    installed=lifecycle.Installed.__new__(lifecycle.Installed);installed.install={'log':'original-run'}
    monkeypatch.setattr(installed,'validate_checkpoint',lambda path:{'install_run':'original-run'})
    with pytest.raises(XocError,match='Installation run is unchanged'):installed.verify(tmp_path/'unused','reinstall',10)


def test_verification_cannot_overlap_installer_or_another_verification(tmp_path):
    path=tmp_path/'installation.lock'
    with lifecycle.installation_lock(path):
        with pytest.raises(XocError,match='already running'):
            with lifecycle.installation_lock(path):pass
    with lifecycle.installation_lock(path):pass
