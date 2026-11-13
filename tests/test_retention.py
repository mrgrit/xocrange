import base64
import json
import os
from pathlib import Path
import pytest
from xocrange.collector import Collector, read_snapshots
from xocrange.event_store import Store
from xocrange.errors import XocError
from xocrange.retention import retained_manager_paths, usage


def test_device_history_never_removes_unread_open_or_recent_logs(tmp_path):
    from xocrange.log_maintenance import history, removable
    import time
    path=tmp_path/'events.log.xoc-01700000000000000000';path.write_bytes(b'line\n')
    os.utime(path,(time.time()-90000,time.time()-90000));info=path.stat()
    key=f'fw:{info.st_dev}:{info.st_ino}'
    assert history(tmp_path/'events.log')==[path]
    assert not removable(path,{},set())
    assert not removable(path,{key:{'offset':3,'buffer':''}},set())
    assert not removable(path,{key:{'offset':5,'buffer':'partial'}},set())
    assert not removable(path,{key:{'offset':5,'buffer':''}},{(info.st_dev,info.st_ino)})
    anchor=base64.b64encode(b'line\n').decode()
    assert removable(path,{key:{'offset':5,'buffer':'','anchor':anchor}},set())
    # A stale cursor left by an earlier file that had the same inode number
    # (different leading bytes, or no anchor at all) does not count as read.
    assert not removable(path,{key:{'offset':5,'buffer':'','anchor':base64.b64encode(b'other\n').decode()}},set())
    assert not removable(path,{key:{'offset':5,'buffer':''}},set())
    os.utime(path,None)
    assert not removable(path,{key:{'offset':5,'buffer':'','anchor':anchor}},set())

FIXTURES = Path(__file__).parent/'fixtures/events'


def test_full_store_does_not_advance_input_and_resumes_after_capacity_change(tmp_path):
    c = Collector.__new__(Collector); c.store = Store(tmp_path/'store')
    source=tmp_path/'eve.json';source.write_bytes(json.dumps(json.loads((FIXTURES/'suricata-alert.json').read_bytes())).encode()+b'\n')
    chunk=read_snapshots(str(source),'ips',{})[0]
    c.store.policy['ingest_bytes']=1
    with pytest.raises(XocError, match='budget'):
        with c.store.transaction():c.accept_chunk('suricata','ips',chunk)
    assert c.store.cursor(chunk['key']) is None
    c.store.policy['ingest_bytes']=1024**3
    with c.store.transaction():c.accept_chunk('suricata','ips',chunk)
    assert len(c.store.query())==1
    with c.store.transaction():c.accept_chunk('suricata','ips',chunk)
    assert len(c.store.query())==1


def test_disk_reserve_is_fail_closed(tmp_path,monkeypatch):
    from xocrange import retention
    store=Store(tmp_path/'store')
    monkeypatch.setattr(retention,'usage',lambda s:{'used_bytes':0,'filesystem_free_bytes':0})
    with pytest.raises(XocError) as error:
        with store.transaction():store.ingest('suricata','ips','1',(FIXTURES/'suricata-alert.json').read_bytes())
    assert error.value.code=='disk_reserve' and not store.query()


def test_retention_preserves_pending_and_quarantines_until_expiry(tmp_path):
    store=Store(tmp_path/'store')
    with store.transaction():
        for n in range(2):store.ingest('suricata','ips',str(n),(FIXTURES/'suricata-alert.json').read_bytes(),observed='2000-01-01T00:00:00Z')
        store.db.execute('UPDATE events SET confirmed=?,indexed=? WHERE id=(SELECT MIN(id) FROM events)',('2000-01-01','2000-01-01'))
        store.set_cursor('indexer-enabled',True)
    store.prune()
    assert len(store.query())==1 and len(store.pending())==1


def test_pruned_space_returns_to_the_filesystem(tmp_path):
    store=Store(tmp_path/'store')
    assert store.db.execute('PRAGMA auto_vacuum').fetchone()[0]==2
    raw=(FIXTURES/'suricata-alert.json').read_bytes()
    with store.transaction():
        for n in range(300):store.ingest('suricata','ips',str(n),raw,observed='2000-01-01T00:00:00Z')
        store.db.execute('UPDATE events SET confirmed=?,indexed=?',('2000-01-01','2000-01-01'))
        store.set_cursor('indexer-enabled',True)
    before=store.db.execute('PRAGMA page_count').fetchone()[0]
    store.prune()
    assert store.db.execute('PRAGMA freelist_count').fetchone()[0]==0
    assert store.db.execute('PRAGMA page_count').fetchone()[0]<before


def test_budgeted_prune_stops_at_the_deadline_and_resumes(tmp_path, monkeypatch):
    from xocrange import event_store
    store=Store(tmp_path/'store')
    raw=(FIXTURES/'suricata-alert.json').read_bytes()
    with store.transaction():
        for n in range(40):store.ingest('suricata','ips',str(n),raw,observed='2000-01-01T00:00:00Z')
        store.db.execute('UPDATE events SET confirmed=?,indexed=?',('2000-01-01','2000-01-01'))
        store.set_cursor('indexer-enabled',True)
    import itertools
    clock=itertools.count()  # one tick per deadline check
    monkeypatch.setattr(event_store.time,'monotonic',lambda:next(clock))
    count=lambda:store.db.execute('SELECT (SELECT count(*) FROM events)+(SELECT count(*) FROM records)').fetchone()[0]
    assert store.prune(budget=0) is False and count()==80
    passes=[]
    while not store.prune(budget=8,batch=5):
        passes.append(count());assert len(passes)<100
    assert len(passes)>=3 and passes==sorted(passes,reverse=True) and passes[0]<80
    assert count()==0 and store.db.execute('PRAGMA freelist_count').fetchone()[0]==0


def test_collector_runs_file_retention_only_after_the_store_pass_completes(monkeypatch):
    from xocrange import retention
    calls=[]
    class FakeStore:
        def __init__(self):self.results=[False,False,True]
        def prune(self,budget):calls.append(('prune',budget));return self.results.pop(0)
        def health(self,source,status):calls.append((source,status))
    monkeypatch.setattr(retention,'maintain',lambda collector:'ready')
    collector=Collector.__new__(Collector);collector.store=FakeStore()
    assert [collector.maintain() for _ in range(3)]==[False,False,True]
    assert calls==[('prune',3),('prune',3),('prune',3),('retention','ready')]


def test_wazuh_dated_hardlinks_recover_unread_tail_without_duplicates(tmp_path):
    parent=tmp_path/'alerts';history=parent/'2026/Nov';history.mkdir(parents=True)
    active=parent/'alerts.json';active.write_bytes(b'first\nlast\n')
    dated=history/'ossec-alerts-07.json';os.link(active,dated)
    first=read_snapshots(str(active),'wazuh',{},limit=6)[0]
    states={first['key']:{'offset':6,'anchor':first['anchor']}}
    active.unlink();active.write_bytes(b'new\n')
    os.link(active,history/'ossec-alerts-07-001.json')
    chunks=read_snapshots(str(active),'wazuh',states,history=retained_manager_paths(active))
    assert {base64.b64decode(c['data']) for c in chunks}=={b'last\n',b'new\n'}
    assert len({c['key'] for c in chunks})==2


def test_manager_history_rejects_symlink_and_wrong_names(tmp_path):
    parent=tmp_path/'archives';month=parent/'2026/Nov';month.mkdir(parents=True)
    (month/'ossec-archive-07.json').write_text('ok')
    (month/'ossec-archive-08.json').symlink_to('/etc/passwd')
    (month/'arbitrary.json').write_text('not-log')
    assert [p.name for p in retained_manager_paths(parent/'archives.json')]==['ossec-archive-07.json']


def test_policy_rejects_unknown_or_unsafe_settings(tmp_path):
    directory=tmp_path/'store';directory.mkdir(mode=0o700)
    path=directory/'retention.json';path.write_text('{"days":0}');path.chmod(0o600)
    with pytest.raises(XocError):Store(directory)
    path.write_text('{"days":2}');path.chmod(0o644)
    with pytest.raises(XocError):Store(directory)


def test_gzip_rotation_resumes_plain_file_offset(tmp_path):
    import gzip
    parent=tmp_path/'archives';month=parent/'2026/Nov';month.mkdir(parents=True)
    dated=month/'ossec-archive-07.json';dated.write_bytes(b'first\nlast\n')
    chunk=read_snapshots(str(parent/'archives.json'),'archive',{},limit=6,history=[dated])[0]
    states={chunk['key']:{'file':str(dated),'offset':6,'anchor':chunk['anchor']}}
    compressed=Path(str(dated)+'.gz');compressed.write_bytes(gzip.compress(dated.read_bytes()));dated.unlink()
    result=read_snapshots(str(parent/'archives.json'),'archive',states,history=retained_manager_paths(parent/'archives.json'))
    assert len(result)==1 and result[0]['key']==chunk['key']
    assert base64.b64decode(result[0]['data'])==b'last\n' and result[0]['complete']


def test_index_retry_batch_serves_old_and_fresh_without_starvation(tmp_path):
    store=Store(tmp_path/'store')
    with store.transaction():
        for n in range(12):store.ingest('suricata','ips',str(n),(FIXTURES/'suricata-alert.json').read_bytes(),observed=f'2026-11-07T00:00:{n:02}Z')
        store.db.execute("UPDATE events SET confirmed='yes'")
    rows=store.index_batch(limit=4)
    assert [r['observed'][-3:] for r in rows]==['11Z','00Z','01Z','02Z']


def test_archive_cleanup_preserves_unread_and_active_files(tmp_path):
    from xocrange.retention import maintain
    c=Collector.__new__(Collector);c.store=Store(tmp_path/'store');c.indexer=None
    volume=tmp_path/'logs';month=volume/'alerts/2026/Nov';month.mkdir(parents=True)
    (volume/'archives').mkdir()
    c.volumes={'siem':('project_siem-logs',volume,'/var/ossec/logs')}
    for suffix in ('001','002','003'):
        path=month/f'ossec-alerts-07-{suffix}.json';path.write_text('log\n');os.utime(path,(1,1))
        if suffix!='002':
            stat=path.stat()
            with c.store.transaction():c.store.set_cursor(f'wazuh-alerts:project_siem-logs:{stat.st_dev}:{stat.st_ino}',{'offset':4,'buffer':''})
    os.link(month/'ossec-alerts-07-003.json',volume/'alerts/alerts.json')
    assert maintain(c)=='ready'
    assert not (month/'ossec-alerts-07-001.json').exists()
    assert (month/'ossec-alerts-07-002.json').exists() and (month/'ossec-alerts-07-003.json').exists()


def test_malformed_analysis_is_quarantined_without_poisoning_later_records(tmp_path):
    c=Collector.__new__(Collector);c.store=Store(tmp_path/'store')
    path=tmp_path/'alerts.json'
    valid={'id':'1','timestamp':'2026-11-07T00:00:00Z','manager':{'name':'xoc'},'rule':{'id':'5710'},'full_log':'probe'}
    path.write_bytes(b'not-json\n'+json.dumps(valid).encode()+b'\n')
    chunk=read_snapshots(str(path),'wazuh',{})[0]
    with c.store.transaction():c.accept_chunk('wazuh','wazuh-alerts',chunk)
    assert c.store.db.execute('SELECT COUNT(*) FROM wazuh_alerts').fetchone()[0]==1
    assert c.store.db.execute('SELECT raw FROM processing_errors').fetchone()[0]==b'not-json\n'
    assert c.store.cursor(chunk['key'])['offset']==path.stat().st_size
    assert c.store.status()['analysis_quarantined']==1


def test_periodic_retention_health_has_its_own_deadline(tmp_path):
    from datetime import datetime,timezone,timedelta
    from xocrange.event_store import Store
    store=Store(tmp_path/'state');store.health('retention','ready');store.health('source','ready')
    def age(seconds):
        stamp=(datetime.now(timezone.utc)-timedelta(seconds=seconds)).isoformat()
        store.db.execute("UPDATE health SET checked=? WHERE source='retention'",(stamp,));store.db.commit()
    age(310);assert store.status()['status']=='ready'
    age(601);assert store.status()['status']=='degraded'
    store.health('retention','maintenance_failed');assert store.status()['status']=='degraded'


def test_delivery_batches_do_not_scan_already_delivered_history(tmp_path):
    store=Store(tmp_path/'store')
    raw=(FIXTURES/'suricata-alert.json').read_bytes()
    with store.transaction():
        for n in range(2500):store.ingest('suricata','ips',str(n),raw)
        store.db.execute("UPDATE events SET confirmed='done',indexed='done'")
    ticks=[]
    def bounded_work():
        ticks.append(1)
        return int(len(ticks)>50)
    store.db.set_progress_handler(bounded_work,100)
    try:
        assert store.pending()==[] and store.index_batch()==[]
    finally:store.db.set_progress_handler(None,0)
    with store.transaction():store.ingest('suricata','ips','new',raw)
    pending=store.pending();assert len(pending)==1
    with store.transaction():store.db.execute("UPDATE events SET confirmed='done' WHERE id=?",(pending[0]['id'],))
    assert [r['id'] for r in store.index_batch()]==[pending[0]['id']]


def test_live_log_gets_budget_while_old_generation_drains(tmp_path):
    c=Collector.__new__(Collector);c.store=Store(tmp_path/'store');c.volumes={}
    active=tmp_path/'audit.log';active.write_bytes(b'fresh\n')
    old=tmp_path/'audit.log.1';old.write_bytes(b'x'*(3*1024**2))
    chunks=c.read_files('host-auditd',None,None,str(active))
    assert chunks[0]['file']==str(active) and base64.b64decode(chunks[0]['data'])==b'fresh\n'
    historical=next(row for row in chunks if row['file']==str(old))
    assert historical['offset']==0 and len(base64.b64decode(historical['data']))==2*1024**2


def test_orphan_text_renditions_are_removed_after_their_json(tmp_path):
    import time
    from xocrange.retention import remove_orphan_text
    month=tmp_path/'alerts/2026/Nov';month.mkdir(parents=True)
    old=time.time()-5*86400
    for name in ('ossec-alerts-07-046.log.gz','ossec-alerts-08.log','ossec-alerts-08.json','ossec-alerts-09.log.gz'):
        (month/name).write_bytes(b'x')
    for name in ('ossec-alerts-07-046.log.gz','ossec-alerts-08.log','ossec-alerts-08.json'):
        os.utime(month/name,(old,old))
    removed=remove_orphan_text(tmp_path/'alerts/alerts.json',time.time()-2*86400)
    # Only the old text whose JSON is gone; a twin-backed or recent file stays.
    assert removed==1 and sorted(p.name for p in month.iterdir())==['ossec-alerts-08.json','ossec-alerts-08.log','ossec-alerts-09.log.gz']
