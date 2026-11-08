"""Live Fire uses real owner records, while scoring remains an engine concern."""
import pytest
from test_academy import academy,app,application,registry_files,send,login,png,CID
SID='xoc-web-01'
MID=SID+'-red-01'


def report(**changes):
    return dict(course=CID,lesson=SID,mission=MID,scope='livefire',input="curl 'http://target/?q=1%27+OR+1=1--'",output='<script>alert(1)</script>\nHTTP 403\n'+('관측 로그\n'*500),interpretation='차단 응답과 같은 시각의 로그를 연결했다.',status='draft',revision=0,save_mode='auto')|changes


def test_partial_draft_register_revision_and_reopen(academy):
    from control.models import MissionRecord,MissionRevision
    partial=report(output='',interpretation='')
    r=send(academy,'academy/records',partial);assert r.status_code==201
    d=r.json();rid=d['id'];assert not d['versions'] and d['scope']=='livefire'
    # Partial drafts are usable; registration requires every part.
    for missing in ('input','output','interpretation'):
        assert send(academy,'academy/records/'+rid,report(revision=1,status='complete',save_mode='manual',**{missing:''})).status_code==400
    d=send(academy,'academy/records/'+rid,report(revision=1,status='complete',save_mode='manual')).json()
    assert d['status']=='complete' and d['revision']==2 and d['evaluation']['ai_available'] is False
    assert d['input']==report()['input'] and d['output']==report()['output']
    assert MissionRecord.objects.count()==1 and MissionRevision.objects.count()==1
    row=academy.get(f'/core/api/academy/scenarios/{CID}/{SID}/records').json()['records'][0]
    assert row==d
    assert academy.get('/core/api/academy').json()['courses'][0]['completed']==0
    assert send(academy,'academy/records/'+rid,report(revision=1)).status_code==409
    d=send(academy,'academy/records/'+rid,report(revision=2,interpretation='추가 조사 중')).json()
    assert d['status']=='draft' and d['revision']==3
    assert academy.get('/core/api/academy/records/'+rid+'/revisions/2').json()['snapshot']['interpretation']==report()['interpretation']
    assert MissionRevision.objects.count()==1
    send(academy,'logout',{});login(academy)
    assert academy.get('/core/api/academy/records/'+rid).json()['interpretation']=='추가 조사 중'


def test_unique_create_catalog_scope_and_owner(academy):
    from control.models import MissionRecord
    r=send(academy,'academy/records',report()).json();rid=r['id']
    assert send(academy,'academy/records',report()).status_code==409
    assert MissionRecord.objects.count()==1
    assert send(academy,'academy/records',report(lesson='xoc-web-02')).status_code==404
    assert send(academy,'academy/records',report(lesson='discover')).status_code==404
    assert send(academy,'academy/records',report(mission='invented-mission')).status_code==404
    assert send(academy,'academy/records/'+rid,report(scope='mission',revision=1,save_mode='manual',output='HTTP 403')).status_code==404
    send(academy,'logout',{});login(academy,'viewer')
    assert academy.get(f'/core/api/academy/scenarios/{CID}/{SID}/records').json()['records']==[]
    assert academy.get('/core/api/academy/records/'+rid).status_code==404
    assert send(academy,'academy/records/'+rid,report(revision=1)).status_code==404
    assert send(academy,'academy/records',report()).status_code==201


def test_multiple_images_snapshot_and_owner(academy):
    r=send(academy,'academy/records',report(output='')).json();rid=r['id']
    for i in range(4):
        result=send(academy,'academy/records/'+rid+'/images',dict(image=png(),caption='관측 '+str(i),revision=r['revision']))
        assert result.status_code==201;r=result.json()
    assert len(r['images'])==4 and r['versions']==[]
    r=send(academy,'academy/records/'+rid,report(output='',revision=r['revision'],status='complete',save_mode='manual')).json()
    snapshot=academy.get('/core/api/academy/records/'+rid+'/revisions/'+str(r['revision'])).json()['snapshot']
    assert snapshot['images']==[i['id'] for i in r['images']]
    newer=send(academy,'academy/records/'+rid+'/images',dict(image=png(),caption='추가 증거',revision=r['revision'])).json()
    assert newer['status']=='draft' and len(newer['images'])==5
    assert len(academy.get('/core/api/academy/records/'+rid+'/revisions/'+str(r['revision'])).json()['snapshot']['images'])==4
    send(academy,'logout',{});login(academy,'viewer')
    assert academy.get(r['images'][0]['url']).status_code==404
    assert academy.get('/core/api/academy/records/'+rid+'/revisions/'+str(r['revision'])).status_code==404


def test_limits_csrf_and_atomic_audit(academy,monkeypatch):
    from control.models import Audit,MissionRecord
    from django.db import OperationalError
    assert send(academy,'academy/records',report(input='가'*60001)).status_code==400
    assert send(academy,'academy/records',report(),HTTP_X_CSRFTOKEN='').status_code==403
    assert send(academy,'academy/records',report(status='complete')).status_code==400
    def fail(**kwargs):raise OperationalError('injected audit failure')
    monkeypatch.setattr(Audit.objects,'create',fail)
    assert send(academy,'academy/records',report()).status_code==503
    assert not MissionRecord.objects.exists()
