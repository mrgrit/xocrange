"""Exercise actual Django CSRF/session/transaction behavior, not mocked middleware."""
import json
import os
from pathlib import Path
import sys
import time
import pytest


@pytest.fixture(scope='module')
def application(tmp_path_factory):
    directory = tmp_path_factory.mktemp('platform')
    config = directory/'config.json'
    config.write_text(json.dumps({'secret_key':'unit-test-only-not-a-deployed-secret', 'public_host':'xoc.test', 'database':str(directory/'db.sqlite3')}))
    os.environ['XOC_PLATFORM_CONFIG'] = str(config)
    os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'components/platform'))
    import django
    django.setup()
    from django.core.management import call_command
    call_command('migrate', verbosity=0)
    yield


@pytest.fixture
def app(application):
    from django.core.management import call_command
    from django.contrib.auth.models import User
    from django.test import Client
    from control.models import Profile, DevicePolicy
    call_command('flush', verbosity=0, interactive=False)
    for name in ('admin','operator','viewer'):
        user=User.objects.create_user(name,password='Initial-Test-Password-987!')
        Profile.objects.create(user=user,role=name,must_change_password=False)
    for name in ('fw','ips','waf'): DevicePolicy.objects.create(device=name)
    return Client(enforce_csrf_checks=True, HTTP_HOST='platform', HTTP_X_FORWARDED_PROTO='https')


def send(client, path, body, **headers):
    csrf=client.get('/core/api/session').json()['csrf_token']
    options={'HTTP_ORIGIN':'https://xoc.test','HTTP_X_CSRFTOKEN':csrf, **headers}
    return client.post('/core/api/'+path, data=json.dumps(body), content_type='application/json', **options)


def login(client, name='admin'):
    response=send(client,'login',{'username':name,'password':'Initial-Test-Password-987!'})
    assert response.status_code==200, response.content
    return response


@pytest.mark.parametrize('path,body',[('devices/fw',{'write_enabled':True,'version':1}),('users',{'username':'attacker','role':'admin','active':True,'password':'Strong-Test-Password-987!'}),('password',{'current_password':'x','password':'y'}),('logout',{})])
def test_anonymous_changes_rejected(app,path,body):
    assert send(app,path,body).status_code==401


@pytest.mark.parametrize('name',['viewer','operator'])
def test_nonadmins_cannot_change_policy_or_users(app,name):
    login(app,name)
    assert app.get('/core/api/devices').status_code==200
    assert send(app,'devices/fw',{'write_enabled':True,'version':1}).status_code==403
    assert send(app,'users',{'username':'newuser','role':'admin','active':True,'password':'Strong-Test-Password-987!'}).status_code==403
    assert app.get('/core/api/audit').status_code==403


@pytest.mark.parametrize('headers',[{'HTTP_ORIGIN':'https://evil.test'},{'HTTP_X_CSRFTOKEN':''},{'HTTP_SEC_FETCH_SITE':'cross-site'},{'HTTP_ORIGIN':''}])
def test_csrf_rejects_even_login(app,headers):
    assert send(app,'login',{'username':'admin','password':'Initial-Test-Password-987!'},**headers).status_code==403


def test_login_rotates_session_and_sets_secure_cookie(app):
    before=app.session.session_key
    response=login(app)
    cookie=response.cookies['__Host-xoc_session']
    assert cookie['secure'] and cookie['httponly'] and cookie['samesite']=='Strict' and cookie['path']=='/'
    assert app.session.session_key!=before
    assert send(app,'logout',{}).status_code==200
    assert app.get('/core/api/devices').status_code==401


def test_audit_and_policy_are_atomic_and_redacted(app,monkeypatch):
    from control.models import Audit,DevicePolicy
    from django.db import OperationalError
    login(app)
    assert send(app,'devices/fw',{'write_enabled':True,'version':1}).status_code==200
    assert send(app,'devices/fw',{'write_enabled':False,'version':1}).status_code==409
    event=Audit.objects.get(action='device_policy')
    assert event.before=={'write_enabled':False,'version':1}
    assert event.after=={'write_enabled':True,'version':2}
    def unavailable(**kwargs):raise OperationalError('simulated disk failure')
    monkeypatch.setattr(Audit.objects,'create',unavailable)
    assert send(app,'devices/fw',{'write_enabled':False,'version':2}).status_code==503
    assert DevicePolicy.objects.get(device='fw').write_enabled


def test_password_change_revokes_other_sessions(app):
    from django.test import Client
    other=Client(enforce_csrf_checks=True,HTTP_HOST='platform',HTTP_X_FORWARDED_PROTO='https')
    login(app); login(other)
    assert send(app,'password',{'current_password':'Initial-Test-Password-987!','password':'Changed-Strong-Password-123!'}).status_code==200
    assert other.get('/core/api/devices').status_code==401
    assert app.get('/core/api/devices').status_code==200
    from control.models import Audit
    assert 'Password' not in json.dumps(list(Audit.objects.values()),default=str)


def test_role_change_revokes_existing_session(app):
    from django.test import Client
    other=Client(enforce_csrf_checks=True,HTTP_HOST='platform',HTTP_X_FORWARDED_PROTO='https')
    login(app); login(other,'operator')
    assert send(app,'users',{'username':'operator','role':'viewer','active':True}).status_code==200
    assert other.get('/core/api/devices').status_code==401


def test_absolute_session_expiry(app):
    login(app)
    session=app.session; session['authenticated_at']=time.time()-28801;session.save()
    assert app.get('/core/api/devices').status_code==401


def test_force_password_change_and_unknown_fields(app):
    from control.models import Profile
    Profile.objects.filter(user__username='admin').update(must_change_password=True)
    login(app)
    assert app.get('/core/api/devices').status_code==403
    assert send(app,'password',{'current_password':'Initial-Test-Password-987!','password':'New-Strong-Password-994!','role':'admin'}).status_code==400


def test_rate_limit_and_header_identity_spoof(app):
    from control.models import LoginWindow
    LoginWindow.objects.create(key='all',started=time.time(),attempts=100)
    assert send(app,'login',{'username':'admin','password':'Initial-Test-Password-987!'},HTTP_X_FORWARDED_FOR='1.2.3.4').status_code==429
    assert app.get('/core/api/devices',HTTP_X_USER='admin',HTTP_X_ROLE='admin').status_code==401


def test_method_query_and_body_limits(app):
    assert app.put('/core/api/users',content_type='application/json').status_code==405
    assert app.get('/core/api/session?password=secret').status_code==400
    assert app.post('/core/api/login',data='x'*16385,content_type='application/json').status_code==413


def test_unknown_device_and_self_demotion(app):
    login(app)
    assert send(app,'devices/shell',{'write_enabled':True,'version':1}).status_code==404
    assert send(app,'users',{'username':'admin','role':'viewer','active':False}).status_code==403
