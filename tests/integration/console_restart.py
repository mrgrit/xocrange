#!/usr/bin/env python3
"""Restart real device containers with non-empty policies, then remove only test entries."""
import importlib.util
import json
from pathlib import Path
import sys
import time
import uuid
from xocrange.lab import Docker,checked_plan
from xocrange.platform_setup import STATE
from xocrange.ui_setup import private_json
from admin_credential import admin_password


def verify(root,name,output):
    spec=importlib.util.spec_from_file_location('probe',root/'scripts/verify-platform.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    secret=private_json(STATE/'credentials.json');s=m.Session(secret['public_host']);assert s.login('admin',admin_password(secret))[0]==200
    directory,plan=checked_plan(root,name);engine=Docker(directory/'compose.yaml',plan['compose']['name'])
    checks={};created={};nonce='xoc-restart-'+uuid.uuid4().hex[:12]
    def call(path,body=None):
        r=s.request('/core/api/'+path,body)
        if r[0]!=200:raise AssertionError(str((path,r[0],r[1])))
        return r[1]
    def state(d):return call('console/'+d)
    def mutate(d,payload):
        v=state(d)['version'];p=call('console/'+d+'/preview',{'version':v,'payload':payload})
        call('console/'+d+'/apply',{'version':v,'token':p['token']})
    policies=call('devices')['devices'];before={d:state(d) for d in ('fw','ips','waf')}
    try:
        for p in policies:call('devices/'+p['device'],{'version':p['version'],'write_enabled':True})
        fields={'fw':{'saddr':'198.51.100.244','daddr':'203.0.113.244','proto':'tcp','dport':'65000','action':'drop'},
                'ips':{'proto':'http','buffer':'http.uri','content':nonce+'-ips','action':'drop'},
                'waf':{'variable':'REQUEST_URI','operator':'@contains','pattern':nonce+'-waf','action':'deny'}}
        for d in fields:
            mutate(d,{'operation':'upsert','kind':'rule','name':nonce+'-'+d,'fields':fields[d]})
            current=state(d);created[d]=next(r['id'] for r in current['rules'] if r['name']==nonce+'-'+d)
        saved={d:state(d) for d in fields}
        # Restart only this dedicated project's devices and common UI, retaining volumes.
        engine.run(['restart','fw','ips','web','platform'],compose=True,timeout=120)
        for _ in range(60):
            try:
                current={d:state(d) for d in fields};break
            except Exception:time.sleep(2)
        else:raise AssertionError('Device console did not recover after restart')
        for d in fields:
            checks[d+'_policy_and_revision_preserved']=all(current[d][k]==saved[d][k] for k in ('version','rules','objects','nat'))
            checks[d+'_running_rule_restored']=('xoc:'+created[d] if d=='fw' else nonce+'-'+d) in current[d]['raw']
        checks['session_preserved']=call('session')['authenticated']
        def probe(path):
            code="import urllib.request,urllib.error,json;u=urllib.request.Request('http://172.29.10.1:8080' + %r,headers={'Host':'sample.xoc.test'});\ntry:r=urllib.request.urlopen(u,timeout=4);print(json.dumps({'status':r.status}))\nexcept urllib.error.HTTPError as e:print(json.dumps({'status':e.code}))\nexcept Exception:print(json.dumps({'status':None}))" % path
            return json.loads(engine.run(['exec','-T','lab-client','python','-B','-c',code],compose=True)).get('status')
        checks['ips_blocks_after_restart']=probe('/'+nonce+'-ips') is None
        checks['waf_blocks_after_restart']=probe('/'+nonce+'-waf')==403
        checks['normal_traffic_after_restart']=probe('/')==200

        # A second configtest after restart must still validate the persisted configuration.
        for d in fields:
            p=call('console/'+d+'/preview',{'version':current[d]['version'],'payload':{'operation':'delete','kind':'rule','id':created[d]}})
            checks[d+'_post_restart_configtest']=p['valid']
    finally:
        for d,id in created.items():
            mutate(d,{'operation':'delete','kind':'rule','id':id})
            after=state(d);checks[d+'_test_policy_removed']=all(after[k]==before[d][k] for k in ('rules','objects','nat'))
        for p in policies:
            latest=next(x for x in call('devices')['devices'] if x['device']==p['device'])
            call('devices/'+p['device'],{'version':latest['version'],'write_enabled':p['write_enabled']})
        call('logout',{})
    result={'status':'passed' if all(checks.values()) else 'failed','checks':checks,'scope':'Actual fw/ips/web/platform container restart with non-empty policies; not a host reboot or full module uninstall test.'}
    output.write_text(json.dumps(result,indent=2)+'\n');return result


if __name__=='__main__':
    report=verify(Path(sys.argv[1]),sys.argv[2],Path(sys.argv[3]));print(json.dumps(report,indent=2));raise SystemExit(report['status']!='passed')
