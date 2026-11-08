import json
from test_academy import academy, payload, png, CID
from test_platform_security import application, app, login, send
from test_registry import registry_files


def note(**changes):
    return payload(mission='',scope='lesson',input='',output='',interpretation='',
                   notebook=json.dumps([{'id':'text-1','type':'paragraph','text':'실습 과정\n전체 결과\n나의 해석'}]),**changes)


def test_autosave_recovers_latest_document_without_consuming_manual_history(academy):
    from control.models import MissionRecord,MissionRevision
    r=send(academy,'academy/records',note(save_mode='auto')).json()
    assert r['scope']=='lesson' and len(r['notebook'])==1 and r['versions']==[]
    # Autosave revision numbers must not hit the old 200-save limit.
    MissionRecord.objects.filter(pk=r['id']).update(revision=250)
    blocks=[{'id':'text-1','type':'code','text':'before\nafter\n'*5000}]
    body=note(save_mode='auto',revision=250);body['notebook']=json.dumps(blocks)
    response=send(academy,'academy/records/'+r['id'],body)
    assert response.status_code==200 and response.json()['revision']==251
    assert MissionRevision.objects.count()==0
    lesson=academy.get('/core/api/academy/lessons/'+CID+'/case-01').json()
    assert lesson['notebook']['notebook']==blocks
    body.update(save_mode='manual',revision=251,status='complete')
    assert send(academy,'academy/records/'+r['id'],body).status_code==200
    assert MissionRevision.objects.count()==1
    assert academy.get('/core/api/academy/courses/'+CID).json()['lessons'][5]['completed']==3
    body['revision']=250
    assert send(academy,'academy/records/'+r['id'],body).status_code==409


def test_multiple_images_interleave_with_text_and_old_versions_remain(academy):
    r=send(academy,'academy/records',note(save_mode='auto')).json();blocks=r['notebook']
    for i in range(4):
        r=send(academy,'academy/records/'+r['id']+'/images',{'image':png(),'caption':'검색 결과','revision':r['revision']}).json()
        blocks += [{'id':f'image-{i}','type':'image','image_id':r['images'][-1]['id'],'text':f'결과 {i}'},
                   {'id':f'paragraph-{i}','type':'paragraph','text':'화면 해석과 다음 검색 과정'}]
    body=note(revision=r['revision'],status='complete');body['notebook']=json.dumps(blocks)
    response=send(academy,'academy/records/'+r['id'],body);assert response.status_code==200
    saved=response.json();assert len(saved['images'])==4 and len(saved['notebook'])==9
    version=saved['revision'];body['revision']=version;body['notebook']=json.dumps(list(reversed(blocks)))
    assert send(academy,'academy/records/'+r['id'],body).status_code==200
    old=academy.get(f"/core/api/academy/records/{r['id']}/revisions/{version}").json()
    assert old['snapshot']['notebook']==blocks
    # Images belong to the exact notebook, not just the same user.
    other=send(academy,'academy/records',note()).json()
    bad=note(revision=other['revision']);bad['notebook']=json.dumps(blocks)
    assert send(academy,'academy/records/'+other['id'],bad).status_code==400
    send(academy,'logout',{});login(academy,'viewer')
    assert academy.get('/core/api/academy/records/'+r['id']).status_code==404
    assert academy.get(saved['images'][0]['url']).status_code==404


def test_document_shape_size_and_write_boundary(academy):
    for blocks in ({},[{'id':'x','type':'html','text':'<script>x</script>'}],
                   [{'id':'x','type':'paragraph','text':'가'*90000}],
                   [{'id':'x','type':'image','text':'','image_id':[]}],
                   [{'id':'x','type':'paragraph','text':'a'}]*2):
        body=note();body['notebook']=json.dumps(blocks,ensure_ascii=False)
        assert send(academy,'academy/records',body).status_code==400
    empty=note(status='complete');empty['notebook']='[]'
    assert send(academy,'academy/records',empty).status_code==400
    assert send(academy,'academy/records',note(save_mode='auto',status='complete')).status_code==400
    assert send(academy,'academy/records',note(),HTTP_X_CSRFTOKEN='').status_code==403


def test_notebook_keeps_legacy_mission_records_separate(academy):
    legacy=send(academy,'academy/records',payload()).json()
    notebook=send(academy,'academy/records',note()).json()
    response=academy.get('/core/api/academy/lessons/'+CID+'/case-01').json()
    assert response['notebook']['id']==notebook['id'] and response['records'][0]['id']==legacy['id']
    assert response['records'][0]['input']==payload()['input']
    body=note(revision=legacy['revision'])
    assert send(academy,'academy/records/'+legacy['id'],body).status_code==404


def test_floor_dashboard_reports_only_my_real_learning_state(academy):
    send(academy,'academy/records',note())
    current=academy.get('/core/api/academy').json()
    assert current['learning_status']['notebooks']==1 and current['learning_status']['drafts']==1
    assert len(current['learning_status']['recent'])==1
    assert sum(s['missions'] for s in current['scenarios'])==105
    assert current['learning_status']['execution_available'] is False
    send(academy,'logout',{});login(academy,'viewer')
    other=academy.get('/core/api/academy').json()['learning_status']
    assert other['notebooks']==0 and other['recent']==[]
