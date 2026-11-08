"""C4 ownership, C5 isolation, observation freshness and optional feature boundaries."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import pytest

from xocrange.errors import XocError
from xocrange.planner import plan
from xocrange.registry import registrations, build_registry, observe
from xocrange.content import bundle
from test_platform_security import application, app, login, send
from test_entitlements import issuer, IDENTITY

ROOT=Path(__file__).resolve().parents[1]
INSTALLATION='976d736b-0ab6-48ef-bc9f-2b1b4c04231a'


def planned(include=('portal','noc','academy-reader','console-fw'), without=()):
    return plan(ROOT,preset='security-path',include=include,without=without,allow_experimental=True)


def test_registry_selection_and_asset_identity_survive_optional_removal():
    full=build_registry(planned(),INSTALLATION)
    small=build_registry(planned(('portal',)),INSTALLATION)
    assert {a['service']:a['asset_id'] for a in full['assets']} == {a['service']:a['asset_id'] for a in small['assets']}
    assert {p['id'] for p in small['panels']} == {'portal'}
    assert {a['floor'] for a in full['assets']} == {'2F'}
    other=build_registry(planned(), '6941b921-9af5-4a57-805f-e8699c6bb928')
    assert not {a['asset_id'] for a in full['assets']} & {a['asset_id'] for a in other['assets']}
    assert all(a['tenant_id']=='community' and a['range_id']=='local' for a in full['assets'])


def test_registry_rejects_ui_collisions_and_route_takeover():
    a={'id':'portal','contracts':{'C4':'0.1.0'},'ui':[{'id':'portal','title':'Home','route':'/core/#portal','floor':None,'permission':'registry.read','order':10}]}
    with pytest.raises(XocError,match='one selected owner'):
        registrations([a,a])
    b=dict(a,id='fixture-echo')
    with pytest.raises(XocError,match='component-owned'):
        registrations([b])
    b['ui']=[dict(a['ui'][0],id='fixture-echo',route='/core/#module/fixture-echo')]
    assert registrations([b])[0]['component_id']=='fixture-echo'
    for route in ('https://evil.test/','//evil.test/','/core/#noc/../../../','javascript:alert(1)'):
        b['ui'][0]['route']=route
        with pytest.raises(XocError): registrations([b])


def test_c4_registration_without_contract_fails():
    with pytest.raises(XocError,match='require C4'):
        registrations([{'id':'portal','ui':[{'id':'portal','title':'Home','route':'/core/#portal','floor':None,'permission':'registry.read','order':0}]}])


@pytest.fixture
def registry_files(app,tmp_path,monkeypatch):
    from django.conf import settings
    data=build_registry(planned(),INSTALLATION)
    files={name:tmp_path/name for name in ('REGISTRY_FILE','OBSERVATION_FILE','BUNDLE_FILE')}
    for name,path in files.items():monkeypatch.setattr(settings,name,str(path),raising=False)
    files['REGISTRY_FILE'].write_text(json.dumps(data))
    files['BUNDLE_FILE'].write_text(json.dumps(bundle(ROOT)))
    health={'schema_version':'xoc.health/0.1.0','plan_id':data['plan_id'],
            'observed_at':datetime.now(timezone.utc).isoformat(),
            'assets':{a['asset_id']:{'state':'running','restarts':0,'secret':'DO-NOT-EXPOSE'} for a in data['assets']}}
    files['OBSERVATION_FILE'].write_text(json.dumps(health))
    return data,files,health


@pytest.mark.parametrize('path',['registry','noc','library','library/getting-started'])
def test_workspace_requires_authenticated_session(app,registry_files,path):
    response=app.get('/core/api/'+path)
    assert response.status_code==401
    assert 'components' not in app.get('/core/api/session').json()
    assert 'navigation' not in app.get('/core/api/session').json()


def test_viewer_inventory_and_reader_have_no_write_actions(app,registry_files):
    login(app,'viewer')
    r=app.get('/core/api/registry');assert r.status_code==200
    d=r.json();assert d['observation']['fresh']
    assert all(a['health']['state']=='running' for a in d['assets'])
    assert b'DO-NOT-EXPOSE' not in r.content
    assert 'no-store' in r['Cache-Control']
    assert app.get('/core/api/noc').json()['floor']=='2F'
    listing=app.get('/core/api/library').json()
    ids={a['id'] for a in listing['articles']}
    assert ids=={'getting-started','security-path','policy-workflow'}
    assert app.get('/core/api/library/siem-investigation').status_code==404
    article=app.get('/core/api/library/security-path').json()
    assert {p['id'] for p in article['related_panels']}=={'noc','fw'}
    for endpoint in ('registry','noc','library'):
        assert send(app,endpoint,{}).status_code==405


@pytest.mark.parametrize('mode',['stale','future','wrong_plan','malformed','missing','bad_shape'])
def test_bad_observation_never_displays_old_running_state(app,registry_files,mode):
    data,files,health=registry_files
    if mode=='stale':health['observed_at']=(datetime.now(timezone.utc)-timedelta(seconds=90)).isoformat()
    elif mode=='future':health['observed_at']=(datetime.now(timezone.utc)+timedelta(minutes=1)).isoformat()
    elif mode=='wrong_plan':health['plan_id']='previous-plan'
    elif mode=='bad_shape':health['assets']=[]
    files['OBSERVATION_FILE'].write_text(json.dumps(health) if mode!='malformed' else '{broken')
    if mode=='missing':files['OBSERVATION_FILE'].unlink()
    login(app)
    response=app.get('/core/api/registry');assert response.status_code==200
    value=response.json()
    assert not value['observation']['fresh']
    assert {a['health']['state'] for a in value['assets']}=={'unknown'}


def test_removed_features_leave_no_navigation_or_content(app,registry_files):
    _,files,_=registry_files
    data=build_registry(planned(('console-fw',)),INSTALLATION)
    files['REGISTRY_FILE'].write_text(json.dumps(data))
    login(app)
    assert {p['id'] for p in app.get('/core/api/session').json()['navigation']}=={'fw'}
    assert app.get('/core/api/noc').status_code==404
    assert app.get('/core/api/library').status_code==404
    assert app.get('/core/api/library/getting-started').status_code==404


def test_module_status_removed_route_and_invalid_entitlement(app,registry_files):
    data,files,_=registry_files
    login(app)
    assert app.get('/core/api/modules/platform').status_code == 200
    assert app.get('/core/api/modules/missing').status_code == 404
    data['components'].append({'id':'M7','title':'Paid fixture','version':'1.2.0','commercial':True,'minimum_tier':'live-fire'})
    data['panels'].append({'id':'paid-test','component_id':'M7','route':'/core/#module/M7','title':'Paid fixture','permission':'registry.read','floor':None,'order':900})
    files['REGISTRY_FILE'].write_text(json.dumps(data))
    assert app.get('/core/api/modules/M7').status_code == 403
    assert not any(p['component_id']=='M7' for p in app.get('/core/api/session').json()['navigation'])
    data['components']=[c for c in data['components'] if c['id']!='M7']
    files['REGISTRY_FILE'].write_text(json.dumps(data))
    assert app.get('/core/api/modules/M7').status_code == 404


def test_paid_routes_revalidate_signature_and_expiry_for_each_request(app,registry_files,issuer,tmp_path,monkeypatch):
    from django.conf import settings
    data,files,_=registry_files;sign,keys=issuer
    directory=tmp_path/'license';(directory/'trust').mkdir(parents=True)
    (directory/'identity.json').write_text(json.dumps(IDENTITY))
    (directory/'trust/ephemeral-test.pem').write_text(keys['ephemeral-test'])
    token=directory/'license.json';token.write_text(json.dumps(sign()))
    monkeypatch.setattr(settings,'ENTITLEMENT_DIR',str(directory),raising=False)
    data['components'].append({'id':'M7','title':'Paid fixture','version':'1.2.0','commercial':True,'minimum_tier':'live-fire'})
    data['panels'].append({'id':'paid-test','component_id':'M7','route':'/core/#module/M7','title':'Paid fixture','permission':'registry.read','floor':None,'order':900})
    files['REGISTRY_FILE'].write_text(json.dumps(data));login(app)
    assert app.get('/core/api/modules/M7').json()['access']['mode']=='licensed'
    assert any(p['component_id']=='M7' for p in app.get('/core/api/session').json()['navigation'])
    token.write_text(json.dumps(sign(expires_at='2021-01-01T00:00:00Z')))
    assert app.get('/core/api/modules/M7').json()['access']['mode']=='read-only'
    assert not any(p['component_id']=='M7' for p in app.get('/core/api/session').json()['navigation'])
    damaged=sign();damaged['payload']['tier']='joint-force';token.write_text(json.dumps(damaged))
    assert app.get('/core/api/modules/M7').status_code==403
    assert app.get('/core/api/modules/platform').status_code==200


def test_force_password_change_blocks_inventory_and_revoked_session(app,registry_files):
    from control.models import Profile
    login(app)
    profile=Profile.objects.get(user__username='admin');profile.must_change_password=True;profile.save()
    assert app.get('/core/api/session').json()['navigation']==[]
    assert app.get('/core/api/registry').status_code==403
    profile.generation+=1;profile.save()
    assert app.get('/core/api/registry').status_code==401


def test_reader_uses_article_ids_not_filesystem_paths(app,registry_files):
    login(app)
    assert app.get('/core/api/library/config.json').status_code==404
    assert app.get('/core/api/library/not-installed').status_code==404
    assert app.get('/core/api/library/..%2Fconfig.json').status_code==404


def test_observer_projects_and_fields_are_bounded():
    registry=build_registry(planned(),INSTALLATION)
    class Engine:
        def run(self,args,**kw):
            if args[0]=='ps':return '123456789abc\n'
            assert args[:2]==['inspect','--format']
            assert '{{json .}}' not in args[2] and '.Config.Env' not in args[2]
            return json.dumps(dict(project='xoc-core-security-path',service='fw',status='running',health=None,
                                   restarts=2,started_at='2026-11-08T01:00:00Z',password='NOT-OUTPUT'))
    result=observe(Engine(),'xoc-core-security-path',registry)
    assert 'NOT-OUTPUT' not in json.dumps(result)
    fw=next(a for a in registry['assets'] if a['service']=='fw')
    assert result['assets'][fw['asset_id']]['state']=='running'
    assert sum(v['state']=='missing' for v in result['assets'].values())==len(registry['assets'])-1
    class Invalid:
        def run(self,*args,**kwargs):return '--privileged'
    assert {a['state'] for a in observe(Invalid(),'xoc-core-security-path',registry)['assets'].values()}=={'unknown'}


def test_all_optional_workspaces_can_be_independent():
    for name in ('portal','noc','academy-reader'):
        p=planned((name,))
        assert set(p['lock']['selected'])=={'platform','security-path','management',name}
        assert not any('docker.sock' in v for s in p['compose']['services'].values() for v in s.get('volumes',[]))


def test_corrupt_registry_fails_closed_with_service_error(app,registry_files):
    _,files,_=registry_files
    login(app)
    files['REGISTRY_FILE'].write_text('[]')
    assert app.get('/core/api/registry').status_code==503
    assert app.get('/core/api/session').json()['navigation']==[]


def test_c4_reserves_paid_component_routes_without_granting_entitlement():
    item={'id':'M1','contracts':{'C4':'0.1.0'},'ui':[{'id':'m1','title':'Target pack','route':'/core/#module/M1','floor':'2F','permission':'registry.read','order':80}]}
    assert registrations([item])[0]['route']=='/core/#module/M1'
