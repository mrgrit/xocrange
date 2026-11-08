#!/usr/bin/env python3
"""K07 acceptance through real ingress, IPS and WAF, with secret-log scanning."""
import http.cookiejar
import json
from pathlib import Path
import secrets
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid
from xocrange.lab import Docker, checked_plan
from xocrange.platform_setup import STATE
from xocrange.ui_setup import private_json, write


class Session:
    def __init__(self, host):
        self.host=host;self.csrf='';self.jar=http.cookiejar.CookieJar()
        context=ssl.create_default_context(cafile='/etc/xocrange/ca.crt')
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context),urllib.request.HTTPCookieProcessor(self.jar))

    def request(self,path,body=None,headers=None,method=None):
        h={'Content-Type':'application/json','Origin':'https://'+self.host,'X-CSRFToken':self.csrf,**(headers or {})}
        req=urllib.request.Request('https://127.0.0.1'+path,data=None if body is None else json.dumps(body).encode(),headers=h,method=method or ('POST' if body is not None else 'GET'))
        try:response=self.opener.open(req,timeout=45)
        except urllib.error.HTTPError as error:response=error
        raw=response.read(4*1024**2)
        try:data=json.loads(raw)
        except ValueError:data={}
        if isinstance(data,dict) and data.get('csrf_token'):self.csrf=data['csrf_token']
        return response.status,data,response.headers,raw

    def login(self,name,password):
        self.request('/core/api/session')
        return self.request('/core/api/login',{'username':name,'password':password})


def verify(root,plan_name):
    directory,plan=checked_plan(root,plan_name);engine=Docker(directory/'compose.yaml',plan['compose']['name'])
    credentials=private_json(STATE/'credentials.json');host=credentials['public_host']
    admin=Session(host);anonymous=Session(host);checks={};markers=[]
    checks['anonymous_read_denied']=anonymous.request('/core/api/devices')[0]==401
    anonymous.request('/core/api/session')
    checks['anonymous_write_denied']=anonymous.request('/core/api/devices/fw',{'write_enabled':True,'version':1})[0]==401
    checks['login_csrf_denied']=anonymous.request('/core/api/login',{'username':'admin','password':'wrong'},headers={'X-CSRFToken':''})[0]==403
    code,data,_,_=admin.login('admin',credentials.get('admin_password',credentials['bootstrap_password']))
    checks['login_via_waf']=code==200
    if data.get('must_change_password'):
        password='Xoc-Acceptance!'+secrets.token_urlsafe(24)
        code,_,_,_=admin.request('/core/api/password',{'current_password':credentials['bootstrap_password'],'password':password})
        checks['initial_password_change']=code==200
        if code==200:
            credentials['admin_password']=password
            write(STATE/'credentials.json',json.dumps(credentials))
    checks['secure_session_cookie']=any(c.name=='__Host-xoc_session' and c.secure and c.has_nonstandard_attr('HttpOnly') and c.get_nonstandard_attr('SameSite')=='Strict' for c in admin.jar)
    code,data,_,_=admin.request('/core/api/devices');checks['authenticated_devices_read']=code==200
    policy=next((d for d in data.get('devices',[]) if d['device']=='fw'),None)
    if policy:
        body={'write_enabled':not policy['write_enabled'],'version':policy['version']}
        checks['wrong_origin_denied']=admin.request('/core/api/devices/fw',body,headers={'Origin':'https://evil.example'})[0]==403
        checks['missing_csrf_denied']=admin.request('/core/api/devices/fw',body,headers={'X-CSRFToken':''})[0]==403
        code,data,_,_=admin.request('/core/api/devices/fw',body);checks['admin_change_allowed']=code==200
        checks['stale_change_denied']=admin.request('/core/api/devices/fw',body)[0]==409
        if code==200:checks['policy_restored']=admin.request('/core/api/devices/fw',{'write_enabled':policy['write_enabled'],'version':data['version']})[0]==200
    name='verify_'+uuid.uuid4().hex[:12]
    secret='K07-sensitive-"<script>alert(7)</script>-'+secrets.token_urlsafe(12)
    markers += [secret.encode(),credentials.get('admin_password',credentials['bootstrap_password']).encode()]
    try:
        code,_,_,_=admin.request('/core/api/users',{'username':name,'role':'viewer','active':True,'password':secret})
        checks['password_field_waf_exception']=code==201
        viewer=Session(host);code,_,_,_=viewer.login(name,secret);checks['viewer_login']=code==200
        new_password='Changed-Viewer!'+secrets.token_urlsafe(20);markers.append(new_password.encode())
        checks['viewer_password_change']=viewer.request('/core/api/password',{'current_password':secret,'password':new_password})[0]==200
        checks['viewer_read']=viewer.request('/core/api/devices')[0]==200
        checks['viewer_write_denied']=viewer.request('/core/api/devices/fw',{'write_enabled':True,'version':1})[0]==403
        checks['viewer_users_denied']=viewer.request('/core/api/users')[0]==403
        checks['viewer_audit_denied']=viewer.request('/core/api/audit')[0]==403
        code,_,_,_=admin.request('/core/api/users',{'username':name,'role':'viewer','active':False})
        checks['disable_account']=code==200
        checks['disable_revokes_session']=viewer.request('/core/api/devices')[0]==401
    finally:
        admin.request('/core/api/users',{'username':name,'role':'viewer','active':False})
    checks['other_field_waf_inspection']=admin.request('/core/api/users',{'username':'<script>alert(7)</script>','role':'viewer','active':True,'password':'Valid-Password!123'})[0]==403
    checks['other_route_waf_inspection']=admin.request('/core/api/devices/fw',{'password':'<script>alert(7)</script>'})[0]==403
    query='K07-query-secret-'+uuid.uuid4().hex;markers.append(query.encode())
    checks['query_credentials_rejected']=admin.request('/core/api/session?password='+query)[0]==400
    code,data,_,_=admin.request('/core/api/audit');checks['admin_audit_read']=code==200
    checks['audit_has_before_after']=any(e['action']=='device_policy' and 'version' in e['before'] and 'version' in e['after'] for e in data.get('events',[]))
    # Internal network clients cannot reach management over TCP: only health.
    probe="import urllib.request,urllib.error;\ntry:r=urllib.request.urlopen('http://platform:8080/core/api/devices')\nexcept urllib.error.HTTPError as e:r=e\nprint(r.status)"
    checks['direct_tcp_cannot_bypass']=engine.run(['exec','-T','web','python3','-B','-c',probe],compose=True).strip()=='404'
    checks['no_management_host_port']=all(not service.get('ports') for name,service in plan['compose']['services'].items() if name!='ingress')
    checks['logout']=admin.request('/core/api/logout',{})[0]==200
    checks['logout_revokes']=admin.request('/core/api/devices')[0]==401
    # Do not print found strings. Inspect only this project's logs and DB audit.
    leaked=[]
    for short in ('web-logs','platform-data'):
        volume=json.loads(engine.run(['volume','inspect',plan['compose']['name']+'_'+short]))[0]
        base=Path(volume['Mountpoint'])
        if short=='platform-data':
            import sqlite3
            db=sqlite3.connect(base/'control.sqlite3')
            payload=json.dumps(db.execute('SELECT actor,action,target,before,after FROM control_audit').fetchall()).encode();db.close()
            if any(marker in payload for marker in markers):leaked.append('audit')
        else:
            for path in base.iterdir():
                if path.is_file() and not path.is_symlink():
                    with path.open('rb') as stream:
                        tail=b''
                        while chunk:=stream.read(1024**2):
                            data=tail+chunk
                            if any(marker in data for marker in markers):leaked.append(path.name);break
                            tail=data[-2048:]
    checks['no_plaintext_secrets_in_logs']=not leaked
    report={'status':'passed' if all(checks.values()) else 'failed','checks':checks,'scope':'Real HTTPS/WAF and Django; no K08 device configuration implementation claim.'}
    Path('/var/lib/xocrange/platform-acceptance.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    result=verify(Path(sys.argv[1]),sys.argv[2]);print(json.dumps(result,indent=2));raise SystemExit(0 if result['status']=='passed' else 2)
