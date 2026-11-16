"""Data-center floor boundaries; purchase flags never grant Core access."""
from copy import deepcopy
import json
from datetime import datetime, timedelta, timezone
import pytest
from test_registry import registry_files
from test_platform_security import application, app, login, send

LOCKED=('1F','3F','4F','5F','7F','8F','XOC')

@pytest.mark.parametrize('path',['datacenter','datacenter/floors/2F','datacenter/floors/6F','datacenter/floors/7F','datacenter/design/6F'])
def test_anonymous_cannot_read_floor_inventory(app,registry_files,path):
    assert app.get('/core/api/'+path).status_code==401

@pytest.mark.parametrize('role',['admin','operator','viewer'])
def test_core_floor_and_purchased_spaces_are_server_gated(app,registry_files,role):
    login(app,role)
    response=app.get('/core/api/datacenter');assert response.status_code==200
    data=response.json()
    assert data['tier']=='community' and data['allowed_floors']==['2F','B1','SITE','6F']
    assert set(data['preview_floors'])==(set(LOCKED)|{'6F'} if role=='admin' else set())
    assert {f['id'] for f in data['floors'] if f['enabled']}=={'2F','B1','SITE','6F'}
    floors={f['id']:f for f in data['floors']}
    assert floors['6F']['access_requirement']=='community_bundle_and_purchased_catalog'
    academy=app.get('/core/api/datacenter/floors/6F').json()
    assert academy['entry_route']=='/core/#academy' and academy['assets']==[]
    assert academy['commercial_execution'] is False
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
    assert app.get('/core/api/datacenter/design/7F?'+query).status_code==400


def test_optional_noc_removal_closes_all_visualization_paths(app,registry_files):
    data,files,_=registry_files
    data['components']=[c for c in data['components'] if c['id']!='noc']
    files['REGISTRY_FILE'].write_text(json.dumps(data));login(app)
    assert 'datacenter' not in {p['id'] for p in app.get('/core/api/session').json()['navigation']}
    for path in ('datacenter','datacenter/floors/2F','datacenter/floors/6F','datacenter/floors/7F','datacenter/design/6F'):
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
    assert send(app,'datacenter/design/6F',{}).status_code==405
    profile=Profile.objects.get(user__username='admin');profile.must_change_password=True;profile.save()
    assert app.get('/core/api/datacenter').status_code==403
    assert app.get('/core/api/datacenter/design/6F').status_code==403
    profile.generation+=1;profile.save()
    assert app.get('/core/api/datacenter').status_code==401
    assert app.get('/core/api/datacenter/design/6F').status_code==401


def test_bad_registry_fails_closed(app,registry_files):
    _,files,_=registry_files;files['REGISTRY_FILE'].write_text('[]');login(app)
    assert app.get('/core/api/datacenter').status_code==503
    assert app.get('/core/api/datacenter/design/6F').status_code==503


@pytest.mark.parametrize('role',['admin','operator','viewer'])
def test_design_preview_never_grants_commercial_access(app,registry_files,role):
    login(app,role)
    for floor in LOCKED:
        response=app.get('/core/api/datacenter/design/'+floor)
        assert response.status_code==(200 if role=='admin' else 403)
        if role=='admin':
            d=response.json()
            assert d['floor']['id']==floor and d['preview_only'] is True
            assert d['assets']==[] and d['actions']==[]
            assert d['workspace_design']==(floor in ('6F','7F'))
            assert 'no-store' in response['Cache-Control']
        assert app.get('/core/api/datacenter/floors/'+floor).status_code==403
    if role=='admin':
        for floor in ('2F','unknown'):
            assert app.get('/core/api/datacenter/design/'+floor).status_code==404


def test_racks_and_device_access_follow_selected_inventory(app,registry_files):
    registry,_,_=registry_files
    login(app)
    data=app.get('/core/api/datacenter').json()
    assert [(r['id'],r['position']) for r in data['racks']]==[('R-2F-01',[3,3]),('R-2F-02',[3,5]),('R-2F-03',[5.6,3])]
    assert next(r for r in data['racks'] if r['id']=='R-2F-03')['asset_ids']==[] and not data['network_observation']['fresh']
    ids=[i for r in data['racks'] for i in r['asset_ids']]
    assert len(ids)==len(set(ids))==len(registry['assets'])
    assert set(ids)=={a['asset_id'] for a in registry['assets']}
    for asset in data['assets']:
        assert asset['description']
        assert asset['asset_id'] in next(r['asset_ids'] for r in data['racks'] if r['id']==asset['rack_id'])
        assert asset["access"]["kind"]=="container_via_host" and not asset["access"]["direct_ssh"]
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


def network_document(plan_id, observed_at=None):
    return {'schema_version':'xoc.network/0.1.0','plan_id':plan_id,
            'observed_at':observed_at or datetime.now(timezone.utc).isoformat(),
            'segments':[{'id':'ext','internal':False,'subnet':'10.20.30.0/24','gateway':'10.20.30.254','bridge':'br-16dbbff96956',
                         'state':'up','mtu':1500,'counters':{'rx_packets':5,'tx_packets':7},
                         'endpoints':[{'service':'fw','ip':'10.20.30.1','prefix':24,'mac':'ca:9a:40:c3:9e:dd'}],
                         'mac_table':[{'mac':'ca:9a:40:c3:9e:dd','port':'veth1','owner':'fw'}]},
                        {'id':'pipe','internal':False,'subnet':'10.20.31.0/24','gateway':'10.20.31.254','bridge':'br-$(id)',
                         'state':'down','mtu':1500,'counters':{},'endpoints':[],'mac_table':[]},
                        {'id':'mgmt','subnet':'172.18.0.0/16','state':'up','endpoints':[],'mac_table':[]}],
            'routers':[{'service':'fw','interfaces':[{'name':'eth0','segment':'ext','addresses':['10.20.30.1/24'],'mac':'ca:9a:40:c3:9e:dd'}],
                        'routes':[{'dst':'10.20.32.0/24','via':'10.20.31.2','dev':'eth1'}],'neighbors':[]}]}


def test_lab_switches_and_routing_come_from_a_fresh_host_observation(app,registry_files):
    """ADR 0010: the four lab bridges appear as switches on R-2F-03 and fw/ips/web carry their routing."""
    registry,files,_=registry_files
    login(app,'viewer')
    files['NETWORK_FILE'].write_text(json.dumps(network_document(registry['plan_id'])))
    data=app.get('/core/api/datacenter').json()
    switches=[a for a in data['assets'] if a['kind']=='switch']
    assert [a['asset_id'] for a in switches]==['net-ext','net-pipe']            # unknown segments are not shown
    assert next(r for r in data['racks'] if r['id']=='R-2F-03')['asset_ids']==['net-ext','net-pipe']
    ext,pipe=switches
    assert ext['health']['state']=='running' and pipe['health']['state']=='exited'
    assert ext['access']['kind']=='host_readonly' and 'bridge fdb show br br-16dbbff96956' in ext['access']['shell_command']
    assert pipe['access']['shell_command']=='' and '$(id)' not in json.dumps(pipe['access'])   # unsafe bridge names give no command
    assert ext['segment']['mac_table'][0]['owner']=='fw'
    fw=next(a for a in data['assets'] if a['service']=='fw')
    assert fw['network']['routes'][0]['via']=='10.20.31.2' and '라우터' in fw['description']
    assert data['network_observation']['fresh']
    # A stale or foreign observation shows no switches.
    files['NETWORK_FILE'].write_text(json.dumps(network_document('other-plan')))
    assert not [a for a in app.get('/core/api/datacenter').json()['assets'] if a['kind']=='switch']
    files['NETWORK_FILE'].write_text(json.dumps(network_document(registry['plan_id'],'2026-01-01T00:00:00+00:00')))
    assert not [a for a in app.get('/core/api/datacenter').json()['assets'] if a['kind']=='switch']
    # The observer refreshes the network every 60 s; a view a little older than that is still current.
    recent=(datetime.now(timezone.utc)-timedelta(seconds=100)).isoformat()
    files['NETWORK_FILE'].write_text(json.dumps(network_document(registry['plan_id'],recent)))
    assert app.get('/core/api/datacenter').json()['network_observation']['fresh']


@pytest.mark.parametrize('floor,count',[('B1',15),('SITE',12)])
def test_facility_floors_show_descriptions_and_baseline_only(app,registry_files,floor,count):
    """ADR 0010: Community shows facilities with their guide text and ledger baseline; no simulator."""
    login(app,'viewer')
    data=app.get('/core/api/datacenter/floors/'+floor).json()
    assert data['facility_view'] is True and data['simulator'] is False and data['assets']==[] and data['racks']==[]
    facilities=data['facilities']
    assert len(facilities)==count and all(f['floor']==floor for f in facilities)
    for f in facilities:
        assert f['name'] and f['title'] and f['role'] and f['checks'] and f['system_title'] in ('전력','냉각','물리 보안','소방')
        assert all(set(b)=={'label','value'} and '_' not in b['label'] for b in f['baseline'])   # labelled, no raw keys
    assert set(data['facility_systems'])=={'power','cooling','security','fire'}
    ups=next((f for f in facilities if f['type']=='ups'),None)
    if ups:
        assert {'label':'방식','value':'이중 변환(온라인)'} in ups['baseline']
