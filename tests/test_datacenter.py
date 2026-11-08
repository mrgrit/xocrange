"""Data-center floor boundaries; purchase flags never grant Core access."""
from copy import deepcopy
import json
import pytest
from test_registry import registry_files
from test_platform_security import application, app, login, send

LOCKED=('B1','1F','3F','4F','5F','6F','7F','8F','XOC','SITE')

@pytest.mark.parametrize('path',['datacenter','datacenter/floors/2F','datacenter/floors/6F','datacenter/floors/7F'])
def test_anonymous_cannot_read_floor_inventory(app,registry_files,path):
    assert app.get('/core/api/'+path).status_code==401

@pytest.mark.parametrize('role',['admin','operator','viewer'])
def test_core_floor_and_purchased_spaces_are_server_gated(app,registry_files,role):
    login(app,role)
    response=app.get('/core/api/datacenter');assert response.status_code==200
    data=response.json()
    assert data['tier']=='community' and data['allowed_floors']==['2F']
    assert {f['id'] for f in data['floors'] if f['enabled']}=={'2F'}
    floors={f['id']:f for f in data['floors']}
    assert floors['6F']['access_requirement']=='institution_content_purchase'
    assert floors['7F']['access_requirement']=='institution_scenario_purchase'
    assert floors['8F']['minimum_tier']=='joint-force'
    assert floors['8F']['access_requirement']=='joint_force_virtual_company'
    assert app.get('/core/api/datacenter/floors/2F').json()['assets']==data['assets']
    for floor in LOCKED:
        r=app.get('/core/api/datacenter/floors/'+floor)
        assert r.status_code==403 and 'assets' not in r.json()
    assert 'no-store' in response['Cache-Control']
    assert b'DO-NOT-EXPOSE' not in response.content
    assert all(a['floor']=='2F' and a['tenant_id']=='community' for a in data['assets'])

@pytest.mark.parametrize('query',['tier=joint-force','tenant_id=other','purchased=true','content_id=paid','scenario_id=paid'])
def test_client_cannot_claim_edition_or_purchase(app,registry_files,query):
    login(app)
    assert app.get('/core/api/datacenter?'+query).status_code==400
    assert app.get('/core/api/datacenter/floors/6F?'+query).status_code==400
    assert app.get('/core/api/datacenter/floors/7F?'+query).status_code==400


def test_optional_noc_removal_closes_all_visualization_paths(app,registry_files):
    data,files,_=registry_files
    data['components']=[c for c in data['components'] if c['id']!='noc']
    files['REGISTRY_FILE'].write_text(json.dumps(data));login(app)
    assert 'datacenter' not in {p['id'] for p in app.get('/core/api/session').json()['navigation']}
    for path in ('datacenter','datacenter/floors/2F','datacenter/floors/6F','datacenter/floors/7F'):
        assert app.get('/core/api/'+path).status_code==404


def test_stale_observation_cannot_show_green_and_foreign_assets_not_exposed(app,registry_files):
    data,files,health=registry_files
    for modifications in ({'floor':'6F'},{'tenant_id':'other-institution'},{'range_id':'foreign-range'}):
        extra=deepcopy(data['assets'][0]);extra.update(modifications,asset_id='asset-foreign')
        data['assets'].append(extra)
    files['REGISTRY_FILE'].write_text(json.dumps(data));files['OBSERVATION_FILE'].unlink();login(app)
    d=app.get('/core/api/datacenter').json()
    assert not d['observation']['fresh']
    assert all(a['health']['state']=='unknown' and a['asset_id']!='asset-foreign' for a in d['assets'])


def test_lifecycle_auth_and_invalid_floor(app,registry_files):
    from control.models import Profile
    login(app)
    assert app.get('/core/api/datacenter/floors/unknown').status_code==404
    assert send(app,'datacenter',{}).status_code==405
    assert send(app,'datacenter/floors/2F',{}).status_code==405
    profile=Profile.objects.get(user__username='admin');profile.must_change_password=True;profile.save()
    assert app.get('/core/api/datacenter').status_code==403
    profile.generation+=1;profile.save()
    assert app.get('/core/api/datacenter').status_code==401


def test_bad_registry_fails_closed(app,registry_files):
    _,files,_=registry_files;files['REGISTRY_FILE'].write_text('[]');login(app)
    assert app.get('/core/api/datacenter').status_code==503


def test_racks_and_device_access_follow_selected_inventory(app,registry_files):
    registry,_,_=registry_files
    login(app)
    data=app.get('/core/api/datacenter').json()
    assert [(r['id'],r['position']) for r in data['racks']]==[('R-2F-01',[3,3]),('R-2F-02',[3,5])]
    ids=[i for r in data['racks'] for i in r['asset_ids']]
    assert len(ids)==len(set(ids))==len(registry['assets'])
    assert set(ids)=={a['asset_id'] for a in registry['assets']}
    for asset in data['assets']:
        assert asset['description']
        assert asset['asset_id'] in next(r['asset_ids'] for r in data['racks'] if r['id']==asset['rack_id'])
        assert asset['access']['kind']=='container_via_host' and not asset['access']['direct_ssh']
        assert 'label=com.docker.compose.service='+asset['service'] in asset['access']['shell_command']
        assert asset['web_console'] is None or asset['web_console'] in {p['route'] for p in data['panels']}
    assert next(a for a in data['assets'] if a['service']=='ips')['web_console'] is None
    assert next(a for a in data['assets'] if a['service']=='fw')['web_console']=='/core/#fw/policies'


@pytest.mark.parametrize('username', ['ccc',None,'root;id','$(id)','-oProxyCommand=id'])
def test_ssh_hint_never_accepts_shell_options(app,registry_files,monkeypatch,username):
    from django.conf import settings
    monkeypatch.setitem(settings.CONFIG,'ssh_username',username)
    login(app)
    access=app.get('/core/api/datacenter').json()['host_access']
    assert access['username_hint']==('ccc' if username=='ccc' else None)
    assert access['host']==settings.CONFIG['public_host'] and access['port']==22


def test_service_command_injection_fails_closed(app,registry_files):
    data,files,_=registry_files
    data['assets'][0]['service']='fw;id'
    files['REGISTRY_FILE'].write_text(json.dumps(data));login(app)
    r=app.get('/core/api/datacenter')
    assert r.status_code==503 and 'assets' not in r.json()
