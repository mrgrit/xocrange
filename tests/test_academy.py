import base64
import io
import json
from pathlib import Path
import shutil
import pytest
from test_platform_security import application, app, login, send
from test_registry import registry_files
from xocrange.academy_content import catalog
from xocrange.errors import XocError

ROOT=Path(__file__).resolve().parents[1]
CID='wazuh-threat-hunting'


@pytest.fixture
def academy(app,registry_files,monkeypatch):
    from django.conf import settings
    monkeypatch.setattr(settings,'ACADEMY_DIR',str(ROOT/'contents/academy'),raising=False)
    login(app)
    return app


def payload(**changes):
    return dict(course=CID,lesson='case-01',mission='case-01-execute',input="1' OR 1=1--",output='<script>alert(1)</script>',
                interpretation='차단 로그와 HTTP 응답을 비교했다.',status='draft',revision=0)|changes


def png(width=12,height=8):
    from PIL import Image
    out=io.BytesIO();Image.new('RGB',(width,height),'purple').save(out,format='PNG')
    return 'data:image/png;base64,'+base64.b64encode(out.getvalue()).decode()


def test_approved_boundary_all_pages_and_exact_assets(tmp_path):
    courses,files=catalog(ROOT);c=courses[0]
    assert c['public_pages']==339 and len(c['lessons'])==36 and sum(l['missions'] for l in c['lessons'])==96
    assert all(p.suffix in ('.json','.png') for p in files)
    assert all(max(a['source_pages'])<=339 for a in c['assets'].values())
    shutil.copytree(ROOT/'contents',tmp_path/'contents')
    package=tmp_path/'contents/academy'/CID
    (package/'private-original.pptx').write_bytes(b'must not ship')
    with pytest.raises(XocError) as exc:catalog(tmp_path)
    assert exc.value.code=='academy_undeclared'
    (package/'private-original.pptx').unlink()
    file=package/'lessons/case-30/lesson.json';d=json.loads(file.read_text());d['slides'][-1]['page']=340;file.write_text(json.dumps(d))
    with pytest.raises(XocError) as exc:catalog(tmp_path)
    assert exc.value.code=='academy_boundary'


def test_catalog_lesson_mapping_and_private_assets(academy):
    c=academy.get('/core/api/academy').json()['courses'][0]
    assert c['missions']==96 and c['completed']==0
    l=academy.get('/core/api/academy/lessons/'+CID+'/case-30').json()
    assert l['slides'][-1]['page']==339 and l['explanation']['source']['revision']=='REV01'
    assert academy.get('/core/api/academy/lessons/'+CID+'/case-31').status_code==404
    assert academy.get('/core/api/academy/assets/'+CID+'/source-map.json').status_code==404


def test_record_versions_conflicts_progress_and_owner_boundary(academy):
    from control.models import MissionRecord, MissionRevision
    r=send(academy,'academy/records',payload());assert r.status_code==201
    d=r.json();rid=d['id'];assert d['input']==payload()['input'] and d['output']==payload()['output']
    v=send(academy,'academy/records/'+rid,payload(revision=1,status='complete',interpretation='증거 확인 완료'))
    assert v.status_code==200 and v.json()['revision']==2
    assert send(academy,'academy/records/'+rid,payload(revision=1)).status_code==409
    old=academy.get('/core/api/academy/records/'+rid+'/revisions/1').json()
    assert old['snapshot']['interpretation']==payload()['interpretation']
    assert MissionRevision.objects.count()==2 and MissionRecord.objects.count()==1
    assert academy.get('/core/api/academy').json()['courses'][0]['completed']==1
    assert academy.get('/core/api/academy/history').json()['count']==1
    send(academy,'logout',{});login(academy,'viewer')
    assert academy.get('/core/api/academy/records/'+rid).status_code==404
    assert academy.get('/core/api/academy/records/'+rid+'/revisions/1').status_code==404
    assert send(academy,'academy/records/'+rid,payload(revision=2)).status_code==404
    assert academy.get('/core/api/academy/history').json()['count']==0


def test_complete_requires_input_result_and_interpretation(academy):
    for missing in ('input','output','interpretation'):
        assert send(academy,'academy/records',payload(status='complete',**{missing:''})).status_code==400
    assert send(academy,'academy/records',payload(lesson='case-30',mission='case-01-execute')).status_code==404


def test_screenshot_is_persisted_normalized_and_private(academy):
    from control.models import MissionEvidence
    d=send(academy,'academy/records',payload(output='')).json();rid=d['id']
    r=send(academy,'academy/records/'+rid+'/images',{'image':png(),'caption':'원본 결과 화면','revision':1})
    assert r.status_code==201;d=r.json();image=d['images'][0]
    assert image['width']==12 and image['height']==8 and d['revision']==2
    response=academy.get(image['url']);assert response.status_code==200 and response['Content-Type']=='image/webp'
    assert bytes(MissionEvidence.objects.get().image)==response.content
    assert send(academy,'academy/records/'+rid,payload(output='',status='complete',revision=2)).status_code==200
    send(academy,'logout',{});login(academy,'operator')
    assert academy.get(image['url']).status_code==404
    assert send(academy,'academy/records/'+rid+'/images',{'image':png(),'caption':'','revision':3}).status_code==404


def test_invalid_and_oversized_images_never_enter_db(academy):
    from control.models import MissionEvidence
    rid=send(academy,'academy/records',payload()).json()['id']
    for value in ('data:image/svg+xml;base64,PHN2Zz4=', 'data:image/png;base64,aW52YWxpZA==', png(6001,1)):
        assert send(academy,'academy/records/'+rid+'/images',{'image':value,'caption':'','revision':1}).status_code==400
    assert MissionEvidence.objects.count()==0
    assert send(academy,'academy/records/'+rid+'/images',{'image':'x'*760000,'caption':'','revision':1}).status_code==413


def test_mission_write_is_csrf_protected_and_audit_atomic(academy,monkeypatch):
    from control.models import Audit,MissionRecord
    from django.db import OperationalError
    assert send(academy,'academy/records',payload(),HTTP_X_CSRFTOKEN='').status_code==403
    def fail(**kwargs):raise OperationalError('injected audit failure')
    monkeypatch.setattr(Audit.objects,'create',fail)
    assert send(academy,'academy/records',payload()).status_code==503
    assert MissionRecord.objects.count()==0


def test_unselected_reader_hides_routes_without_deleting_records(academy,registry_files):
    from control.models import MissionRecord
    rid=send(academy,'academy/records',payload()).json()['id']
    data,files,_=registry_files;data['components']=[c for c in data['components'] if c['id']!='academy-reader']
    files['REGISTRY_FILE'].write_text(json.dumps(data))
    assert academy.get('/core/api/academy').status_code==404
    assert academy.get('/core/api/academy/records/'+rid).status_code==404
    assert MissionRecord.objects.count()==1


def test_record_fields_and_other_request_limits_stay_bounded(academy):
    assert send(academy,'academy/records',payload(input='x'*24001)).status_code==400
    assert send(academy,'academy/records',payload(revision=True)).status_code==400
    assert send(academy,'login',{'username':'x'*20000,'password':'x'}).status_code==413
    assert academy.get('/core/api/academy?user=viewer').status_code==400
