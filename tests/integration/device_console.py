#!/usr/bin/env python3
"""Dedicated-VM acceptance: real device mutations through Core HTTPS, restored afterward."""
import importlib.util
import json
from pathlib import Path
import sys
import time
from xocrange.lab import Docker,checked_plan
from xocrange.platform_setup import STATE
from xocrange.ui_setup import private_json, STATE as SIEM_STATE


def verify(root,plan_name,output):
    spec=importlib.util.spec_from_file_location('core_acceptance',root/'scripts/verify-platform.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    secret=private_json(STATE/'credentials.json');client=m.Session(secret['public_host']);checks={}
    checks['login']=client.login('admin',secret.get('admin_password',secret['bootstrap_password']))[0]==200
    siem_secret=private_json(SIEM_STATE/'credentials.json');siem=m.Session(secret['public_host'])
    checks['siem_authenticated']=siem.request('/siem/auth/login',{'username':'admin','password':siem_secret['admin']},headers={'osd-xsrf':'xoc-k08'})[0]==200
    checks['siem_native_session']=siem.request('/siem/api/login',{'idHost':'xoc','force':True},headers={'osd-xsrf':'xoc-k08'})[0]==200
    directory,plan=checked_plan(root,plan_name);engine=Docker(directory/'compose.yaml',plan['compose']['name'])
    def request(device,action=None,body=None):return client.request('/core/api/console/'+device+('/'+action if action else ''),body)
    def ok(device,action=None,body=None):
        code,data,_,_=request(device,action,body)
        if code!=200: raise AssertionError(str((device,action,code,data)))
        return data
    def mutate(device,payload):
        state=ok(device);p=ok(device,'preview',{'version':state['version'],'payload':payload});result=ok(device,'apply',{'version':p['version'],'token':p['token']});return result,p
    def probe(path='/'):
        code="import urllib.request,urllib.error,json;u=urllib.request.Request('http://172.29.10.1:8080' + %r,headers={'Host':'sample.xoc.test'});\ntry:r=urllib.request.urlopen(u,timeout=4);print(json.dumps({'status':r.status}))\nexcept urllib.error.HTTPError as e:print(json.dumps({'status':e.code}))\nexcept Exception:print(json.dumps({'status':None}))" % path
        return json.loads(engine.run(['exec','-T','lab-client','python','-B','-c',code],compose=True))
    policy=client.request('/core/api/devices')[1]['devices'];originals={};changed=[]
    checks['anonymous_denied']=m.Session(secret['public_host']).request('/core/api/console/fw')[0]==401
    try:
        for device in ('fw','ips','waf'):
            originals[device]=ok(device);checks[device+'_live_status']=bool(originals[device]['engine'])
            p=next(x for x in policy if x['device']==device)
            if p['write_enabled']:
                client.request('/core/api/devices/'+device,{'write_enabled':False,'version':p['version']})
            checks[device+'_locked_apply_denied']=request(device,'apply',{'version':originals[device]['version'],'token':'invalid'})[0]==403
            latest=next(x for x in client.request('/core/api/devices')[1]['devices'] if x['device']==device)
            assert client.request('/core/api/devices/'+device,{'write_enabled':True,'version':latest['version']})[0]==200
        cases=[('fw',{'proto':'tcp','saddr':'172.29.10.10','dport':'8080','action':'drop','log':True},'/',None),
               ('ips',{'proto':'http','buffer':'http.uri','content':'xoc-console-ips-check','action':'drop'},'/xoc-console-ips-check',None),
               ('waf',{'variable':'REQUEST_URI','operator':'@contains','pattern':'xoc-console-waf-check','action':'deny'},'/xoc-console-waf-check',403)]
        for device,fields,path,expected in cases:
            state=ok(device);payload={'operation':'upsert','kind':'rule','name':'Console acceptance '+device,'fields':fields}
            p=ok(device,'preview',{'version':state['version'],'payload':payload})
            checks[device+'_preview_configtest']=p['valid'] and ok(device)['version']==state['version']
            checks[device+'_tampered_ticket_denied']=request(device,'apply',{'version':p['version'],'token':'bad'})[0]==409
            ok(device,'apply',{'version':p['version'],'token':p['token']});changed.append(device)
            checks[device+'_stale_apply_denied']=request(device,'apply',{'version':p['version'],'token':p['token']})[0]==409
            checks[device+'_blocks_real_traffic']=probe(path).get('status')==expected
            checks[device+'_management_still_available']=client.request('/core/api/session')[0]==200
            siem_response=siem.request('/siem/api/request',{'id':'xoc','method':'GET','path':'/manager/status','body':{}},headers={'osd-xsrf':'xoc-k08'})
            checks[device+'_siem_still_reachable']=siem_response[0]==200 and not siem_response[1].get('error')
            mutate(device,{'operation':'rollback'});changed.remove(device)
            after=ok(device);checks[device+'_rollback_preserves_original']=all(after[k]==originals[device][k] for k in ('rules','objects','nat'))
            checks[device+'_traffic_recovers']=probe(path).get('status')==200
        for device,fields in [('ips',{'proto':'http','pcre':'/[/' }),('waf',{'variable':'REQUEST_URI','operator':'@rx','pattern':'('})]:
            s=ok(device);code,data,_,_=request(device,'preview',{'version':s['version'],'payload':{'operation':'upsert','kind':'rule','name':'Invalid syntax','fields':fields}})
            checks[device+'_invalid_engine_syntax_rejected']=code==400 and ok(device)['version']==s['version']
        # A real rule editor must accept literal detection strings through WAF while other fields stay inspected.
        s=ok('waf');payload={'operation':'upsert','kind':'rule','name':'XSS signature','fields':{'variable':'ARGS','operator':'@contains','pattern':'<script>alert(9)</script>','action':'deny'}}
        checks['literal_waf_signature_preview']=request('waf','preview',{'version':s['version'],'payload':payload})[0]==200
        payload['name']='<script>alert(9)</script>';checks['unrelated_name_still_waf_inspected']=request('waf','preview',{'version':s['version'],'payload':payload})[0]==403
        for device in ('waf','ips'):
            for index,pattern in enumerate(["' OR 1=1--",'/etc/passwd','; cat /etc/passwd','../../etc/shadow','UNION SELECT password FROM users']):
                fields={'variable':'ARGS','operator':'@contains','pattern':pattern,'action':'deny'} if device=='waf' else {'proto':'http','buffer':'http.uri','content':pattern,'action':'alert'}
                v=ok(device)['version']
                checks[device+'_signature_'+str(index)]=request(device,'preview',{'version':v,'payload':{'operation':'upsert','kind':'rule','name':'Signature validation','fields':fields}})[0]==200

    finally:
        for device in changed:
            try:mutate(device,{'operation':'rollback'})
            except Exception:checks[device+'_cleanup_failed']=False
        for p in policy:
            latest=next(x for x in client.request('/core/api/devices')[1]['devices'] if x['device']==p['device'])
            checks[p['device']+'_write_policy_restored']=client.request('/core/api/devices/'+p['device'],{'write_enabled':p['write_enabled'],'version':latest['version']})[0]==200
        client.request('/core/api/logout',{})
        siem.request('/siem/auth/logout',{},headers={'osd-xsrf':'xoc-k08'})
    report={'status':'passed' if all(checks.values()) else 'failed','checks':checks,'scope':'Actual HTTPS, isolated device namespaces, real traffic block and restore; previous policies retained.'}
    output.write_text(json.dumps(report,indent=2)+'\n');return report


if __name__=='__main__':
    result=verify(Path(sys.argv[1]),sys.argv[2],Path(sys.argv[3]));print(json.dumps(result,indent=2));raise SystemExit(0 if result['status']=='passed' else 2)
