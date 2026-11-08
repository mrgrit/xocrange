#!/usr/bin/env python3
"""Exercise actual Wazuh settings, file editor and logtest through WAF."""
import importlib.util
import json
from pathlib import Path
import sys
import uuid
import urllib.request
from xocrange.ui_setup import STATE, private_json


def verify(source, output):
    spec=importlib.util.spec_from_file_location('platform_probe',source/'scripts/verify-platform.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    secret=private_json(STATE/'credentials.json');session=module.Session(secret['public_host'])
    def request(path,body=None,method=None):
        return session.request(path,body,headers={'osd-xsrf':'xoc-k06'},method=method)
    checks={}
    checks['login']=request('/siem/auth/login',{'username':'admin','password':secret['admin']})[0]==200
    checks['native_session']=request('/siem/api/login',{'idHost':'xoc','force':True})[0]==200
    def api(method,path,body=None):
        return request('/siem/api/request',{'id':'xoc','method':method,'path':path,'body':{} if body is None else body})
    for name,path in [('rules','/rules'),('decoders','/decoders'),('manager_config','/manager/configuration'),('configuration_validation','/manager/configuration/validation')]:
        code,data,_,_=api('GET',path)
        checks[name]=code==200 and not data.get('error')
    name='xoc_k06_'+uuid.uuid4().hex[:12]+'.xml'
    xml='<group name="xoc_k06_validation,"><rule id="112900" level="3"><decoded_as>sshd</decoded_as><match>xoc-safe-rule-probe</match><description>Validation: /etc/shadow detection example</description></rule></group>'
    path='/rules/files/'+name
    try:
        body={'params':{'overwrite':False,'relative_dirname':'etc/rules'},'body':xml,'origin':'raw'}
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,*args,**kwargs):return None
        anonymous=module.Session(secret['public_host']);anonymous.opener.add_handler(NoRedirect())
        checks['anonymous_rule_edit_denied']=anonymous.request('/siem/api/request',{'id':'xoc','method':'PUT','path':path,'body':body},headers={'osd-xsrf':'xoc-k06'})[0] in (401,302)
        code,data,_,_=api('PUT',path,body);checks['rule_create_via_waf']=code==200 and not data.get('error')
        code,data,_,raw=api('GET',path,{'params':{'raw':True,'relative_dirname':'etc/rules'}})
        checks['rule_readback']=code==200 and b'xoc-safe-rule-probe' in raw
        body['params']['overwrite']=True;body['body']=xml.replace('level="3"','level="4"')
        code,data,_,_=api('PUT',path,body);checks['rule_update_via_waf']=code==200 and not data.get('error')
        code,data,_,_=api('GET','/manager/configuration/validation');checks['edited_rules_validate']=code==200 and not data.get('error')
        invalid=dict(body);invalid['body']=xml.replace('detection example','<script>')
        code,data,_,_=api('PUT',path,invalid);checks['malformed_xml_rejected_by_manager']=code==200 and bool(data.get('error'))
        code,data,_,raw=api('GET',path,{'params':{'raw':True,'relative_dirname':'etc/rules'}});checks['invalid_edit_preserves_file']=code==200 and b'xoc-safe-rule-probe' in raw and b'level=\"4\"' in raw
        code,data,_,_=api('PUT','/logtest',{'event':'Nov 07 13:00:00 endpoint sshd[123]: Invalid user xocadvanced from 192.0.2.1 port 4444','log_format':'syslog','location':'xoc-k06-test'})
        checks['logtest_via_waf']=code==200 and '5710' in json.dumps(data)
        wrong=dict(body);wrong['unexpected']='<script>alert(9)</script>'
        checks['unrelated_field_still_blocked']=api('PUT',path,wrong)[0]==403
        checks['unrelated_api_still_blocked']=api('PUT','/agents',body)[0]==403
    finally:
        code,data,_,_=api('DELETE',path,{'params':{'relative_dirname':'etc/rules'}})
        checks['temporary_rule_removed']=code==200 and not data.get('error')
        request('/siem/auth/logout',{})
    report={'status':'passed' if all(checks.values()) else 'failed','checks':checks}
    output.write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    result=verify(Path(sys.argv[1]),Path(sys.argv[2]));print(json.dumps(result,indent=2));raise SystemExit(0 if result['status']=='passed' else 2)
