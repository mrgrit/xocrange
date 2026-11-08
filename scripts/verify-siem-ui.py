#!/usr/bin/env python3
"""Exercise the installed HTTPS ingress, real WAF, Dashboard and Indexer."""
import http.cookiejar
import json
from pathlib import Path
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid

from xocrange.events import SOURCES
from xocrange.indexer import Client
from xocrange.lab import Docker, checked_plan
from xocrange.ui_setup import STATE, private_json


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): return None


def verify(root, plan_name):
    directory,plan=checked_plan(root,plan_name)
    engine=Docker(directory/'compose.yaml',plan['compose']['name'])
    secret=private_json(STATE/'credentials.json')
    jar=http.cookiejar.CookieJar()
    context=ssl.create_default_context(cafile=str(STATE/'ca.pem'))
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPSHandler(context=context),urllib.request.HTTPCookieProcessor(jar))
    checks={}
    def request(path, method='GET', body=None, http=False, headers=None, timeout=130):
        headers={'Content-Type':'application/json','osd-xsrf':'xoc-acceptance',**(headers or {})}
        req=urllib.request.Request(('http' if http else 'https')+'://127.0.0.1'+path,method=method,data=body if isinstance(body,bytes) else None if body is None else json.dumps(body).encode(),headers=headers)
        try: response=opener.open(req,timeout=timeout)
        except urllib.error.HTTPError as error: response=error
        with response: return response.status,response.headers,response.read(8*1024**2)
    path='/siem/app/dashboards?xoc=a%20b'
    code,headers,_=request(path,http=True)
    checks['http_redirect_preserves_path_query']=code==308 and headers.get('Location')=='https://'+secret['public_host']+path
    code,_,_=request('/siem/api/saved_objects/_find?type=dashboard')
    checks['anonymous_api_requires_login']=code in (401,302)
    code,_,_=request('/siem/internal/search/opensearch','POST',{'params':{'index':'xoc-events-*','body':{'highlight':{'fragment_size':2147483647}}}})
    checks['rule_exception_preserves_authentication']=code in (401,302)
    code,_,_=request('/siem/auth/login','POST',{'username':'admin','password':'not-the-generated-password'})
    checks['wrong_password_rejected']=code==401
    code,headers,_=request('/siem/auth/login','POST',{'username':'admin','password':secret['admin']})
    checks['login_through_waf']=code==200
    checks['secure_httponly_session_cookie']=any(c.secure and c.has_nonstandard_attr('HttpOnly') for c in jar)
    code,_,_=request('/siem/api/status')
    checks['authenticated_api']=code==200
    from xocrange.manager_api import ManagerClient
    manager=ManagerClient(engine,plan['compose']['name'])
    token=manager.authenticate()
    code,info=manager.request('GET','/manager/info',token=token)
    checks['native_manager_version']=code==200 and info.get('data',{}).get('affected_items',[{}])[0].get('version')=='v4.14.10'
    code,status=manager.request('GET','/manager/status',token=token)
    daemons=status.get('data',{}).get('affected_items',[{}])[0]
    checks['native_manager_daemons']=code==200 and all(daemons.get(name)=='running' for name in ('wazuh-analysisd','wazuh-db','wazuh-remoted','wazuh-logcollector','wazuh-modulesd','wazuh-execd','wazuh-syscheckd'))
    checks['manager_anonymous_rejected']=manager.request('GET','/manager/info')[0]==401
    checks['manager_default_password_rejected']=manager.request('POST','/security/user/authenticate',basic=('wazuh','wazuh'))[0]==401
    # Run Node inside the real Dashboard image. Neither a wrong server name nor
    # an unrelated CA may connect to the Manager; no credentials are sent.
    tls_probe='''const https=require('https'),fs=require('fs');
const options=JSON.parse(process.argv[1]);
if(options.caFile){options.ca=fs.readFileSync(options.caFile);delete options.caFile;}
const r=https.get({hostname:'siem',port:55000,path:'/',...options},()=>process.exit(2));
r.on('error',e=>process.exit(['ERR_TLS_CERT_ALTNAME_INVALID','UNABLE_TO_VERIFY_LEAF_SIGNATURE','UNABLE_TO_GET_ISSUER_CERT_LOCALLY'].includes(e.code)?0:3));r.setTimeout(10000,()=>process.exit(4));'''
    for name,options in [('manager_wrong_hostname_rejected',{'servername':'untrusted.invalid'}),('manager_wrong_ca_rejected',{'caFile':'/run/xoc-secrets/ca.pem'})]:
        try:
            engine.run(['exec','-T','dashboard','/usr/share/wazuh-dashboard/node/bin/node','-e',tls_probe,json.dumps(options)],compose=True)
            checks[name]=True
        except Exception:checks[name]=False
    code,_,body=request('/siem/api/check-stored-api','POST',{'id':'xoc'})
    connection=json.loads(body).get('data',{}) if code==200 else {}
    checks['native_plugin_manager_connection']=code==200 and connection.get('url')=='https://siem' and bool(connection.get('cluster_info',{}).get('manager')) and not connection.get('apiIsDown')
    checks['native_plugin_hides_service_password']='password' not in connection and manager.credentials['wazuh-wui'].encode() not in body
    checks['native_plugin_session']=request('/siem/api/login','POST',{'idHost':'xoc','force':True})[0]==200
    code,_,body=request('/siem/api/request','POST',{'id':'xoc','method':'GET','path':'/manager/info','body':{}})
    checks['native_plugin_manager_info']=code==200 and b'4.14.10' in body
    code,_,body=request('/siem/api/request','POST',{'id':'xoc','method':'GET','path':'/agents','body':{}})
    checks['native_plugin_agents']=code==200 and b'affected_items' in body
    checks['native_plugin_xss_still_blocked']=request('/siem/api/request','POST',{'id':'xoc','method':'GET','path':'/agents','body':{'search':'<script>alert(1)</script>'}})[0]==403
    code,_,body=request('/siem/app/dashboards')
    checks['dashboard_html']=code==200 and b'<html' in body
    scripts=re.findall(r'<script[^>]+src="([^"]+)"',body.decode(errors='replace'))
    assets=[url for url in scripts if url.startswith('/siem/')][:3]
    checks['static_javascript']=bool(assets) and all(request(url)[0]==200 for url in assets)
    payload={'params':{'index':'xoc-events-*','body':{'size':1,'query':{'match_all':{}},'highlight':{'fields':{'*':{}},'fragment_size':2147483647}}}}
    search='/siem/internal/search/opensearch'
    code,_,body=request(search,'POST',payload)
    checks['discover_highlight_rule_exception']=code==200
    checks['other_search_field_still_inspected']=request(search,'POST',{'query':'2147483647'})[0]==403
    checks['other_path_still_inspected']=request('/siem/internal/search/unrelated','POST',payload)[0]==403
    checks['unrelated_put_still_blocked']=request('/siem/api/unrelated','PUT',{})[0]==403
    checks['xss_still_blocked']=request(search,'POST',{'query':'<script>alert(1)</script>'})[0]==403
    file_query={'params':{'index':'xoc-events-*','body':{'size':1,'query':{'match_phrase':{'process.executable':'/root/.profile'}}}}}
    checks['file_path_investigation_allowed']=request(search,'POST',file_query)[0]==200
    file_query['params']['body']['query']['match_phrase']={'producer':'/root/.profile'}
    checks['unrelated_field_keeps_lfi_detection']=request(search,'POST',file_query)[0]==403
    checks['oversized_request_rejected']=request(search,'POST',{'padding':'x'*1048576})[0]==413
    checks['malformed_json_rejected']=request(search,'POST',b'{"bad":not_json}')[0]==400
    # ModSecurity 2.x issue #2807 returns 500 for premature EOF before phase 2.
    # Verify that exact fail-closed parser path, rather than accepting any 500.
    from xocrange.event_store import now
    parser_since=now()
    code,headers,_=request(search,'POST',b'{"incomplete":')
    parser_request=headers.get('X-Xoc-Request-Id')
    from xocrange.event_store import Store
    store=Store('/var/lib/xocrange/siem')
    deadline=time.monotonic()+30
    parser_evidence=None
    while parser_request and time.monotonic()<deadline:
        # Bound the lookup to this probe; scanning retained multi-GiB evidence
        # can consume the entire deadline before a fresh error is collected.
        parser_evidence=store.db.execute("SELECT ref FROM records INDEXED BY records_observed WHERE observed>=? AND source='apache-error' AND instr(CAST(raw AS TEXT),?)>0 AND instr(CAST(raw AS TEXT),'JSON parser error: parse error: premature EOF')>0 LIMIT 1",(parser_since,parser_request)).fetchone()
        if parser_evidence:break
        time.sleep(1)
    checks['truncated_json_fails_closed_in_waf']=code==500 and parser_evidence is not None
    checks['waf_marker_blocks_siem']=request('/siem/api/status',headers={'X-Xoc-Probe':'waf-block'})[0]==403
    code,headers,_=request('/siem/api/status',headers={'X-Xoc-Client-IP':'198.51.100.99','X-Forwarded-For':'198.51.100.99','X-Forwarded-Proto':'http'})
    request_id=headers.get('X-Xoc-Request-Id')
    deadline=time.monotonic()+30
    source=None
    while request_id and time.monotonic()<deadline:
        row=store.db.execute("SELECT json_extract(event,'$.network.source.ip') FROM events WHERE producer='apache-access' AND json_extract(event,'$.correlation.transaction_id')=?",(request_id,)).fetchone()
        if row:source=row[0];break
        time.sleep(1)
    checks['forwarded_client_header_cannot_be_spoofed']=code==200 and source is not None and source!='198.51.100.99'
    from xocrange.event_store import now
    cutoff=now()
    stopped=False
    try:
        stopped=request('/siem/api/status',headers={'X-Xoc-Probe':'ips-block'},timeout=5)[0] in (502,504)
    except (urllib.error.URLError,TimeoutError,ConnectionError):
        stopped=True
    deadline=time.monotonic()+30
    ips_evidence=None
    while time.monotonic()<deadline:
        ips_evidence=store.db.execute("SELECT id FROM events WHERE producer='suricata' AND observed>=? AND json_extract(event,'$.network.source.ip')='172.29.10.20' AND json_extract(event,'$.rule.id')='1000001' AND json_extract(event,'$.event.outcome')='blocked'",(cutoff,)).fetchone()
        if ips_evidence:break
        time.sleep(1)
    checks['ips_inspects_decrypted_https']=stopped and ips_evidence is not None
    checks['ui_recovers_after_block']=request('/siem/api/status')[0]==200
    store.db.close()
    ident='xoc-acceptance-'+uuid.uuid4().hex
    fields='/siem/api/saved_objects/index-pattern/'+ident
    try:
        code,_,_=request(fields,'POST',{'attributes':{'title':'xoc-events-*','timeFieldName':'timestamp'}})
        checks['create_index_pattern']=code==200
        profile={'attributes':{'fields':json.dumps([{'name':'test.profile','type':'string','searchable':True,'aggregatable':True}])}}
        checks['field_definition_rule_exceptions']=request(fields,'PUT',profile)[0]==200
        checks['wrong_method_gets_no_field_exception']=request(fields,'POST',profile)[0]==403
        checks['other_attribute_still_inspected']=request(fields,'PUT',{'attributes':{'title':'test.profile'}})[0]==403
        # A saved-object field list above the historical 128 KiB limit.
        large={'attributes':{'fields':json.dumps([{'name':'field'+str(i),'type':'string','searchable':True,'aggregatable':True} for i in range(2000)])}}
        checks['large_field_list_allowed']=request(fields,'PUT',large)[0]==200
    finally:
        code,_,_=request(fields,'DELETE')
        checks['temporary_object_deleted']=code in (200,404)
    client=Client(engine,plan['compose']['name'],user='admin')
    since=json.loads(Path('/var/lib/xocrange/siem-acceptance.json').read_text())['since']
    deadline=time.monotonic()+180
    while True:
        code,data=client.request('POST','/xoc-events-*/_search',{'size':0,'query':{'range':{'observed_at':{'gte':since}}},'aggs':{'sources':{'terms':{'field':'producer','size':8}}}})
        found={b['key'] for b in data.get('aggregations',{}).get('sources',{}).get('buckets',[])}
        if set(SOURCES)<=found or time.monotonic()>=deadline: break
        time.sleep(3)
    checks['all_eight_fresh_sources_indexed']=code==200 and set(SOURCES)<=found
    deadline=time.monotonic()+180
    while True:
        code,data=client.request('POST','/wazuh-alerts-4.x-*/_search',{'size':0,'query':{'range':{'timestamp':{'gte':since}}},'aggs':{'sources':{'terms':{'field':'data.producer','size':8}}}})
        found={b['key'] for b in data.get('aggregations',{}).get('sources',{}).get('buckets',[])}
        if set(SOURCES)<=found or time.monotonic()>=deadline:break
        time.sleep(3)
    checks['native_alerts_contain_all_eight_c1_links']=code==200 and set(SOURCES)<=found
    # Normal audit/firewall/access records can legitimately produce no alert.
    # Native processing for all eight sources is proven by archive receipts;
    # the following actual detections must also reach the searchable index.
    expected_raw={'suricata':'86601','modsecurity':'119672','sysmon':'111201','apache-error':'30411'}
    deadline=time.monotonic()+180
    while True:
        raw_found=set()
        # Query each producer explicitly: a global first 100 can contain only
        # Sysmon under load even when every rare-source detection is indexed.
        for source,rule in expected_raw.items():
            code,data=client.request('POST','/wazuh-alerts-4.x-*/_search',{'size':1,
                'query':{'bool':{'filter':[{'term':{'xoc.analysis_route':'raw'}},{'range':{'timestamp':{'gte':since}}},
                    {'term':{'xoc.producer':source}},{'term':{'rule.id':rule}},
                    {'exists':{'field':'xoc.input_id'}},{'exists':{'field':'xoc.evidence_ref'}}]}}})
            if code==200 and data.get('hits',{}).get('hits'):raw_found.add(source)
        if set(expected_raw)<=raw_found or time.monotonic()>=deadline:break
        time.sleep(3)
    for source in expected_raw:checks['raw_'+source+'_alert_indexed_with_evidence']=source in raw_found
    # Exercise a stock decoder/rule independently of C1. This is an explicitly
    # synthetic syslog probe, not an SSH attempt or a modification of host users.
    marker='xocprobe'+uuid.uuid4().hex[:12]
    line=time.strftime('%b %d %H:%M:%S')+' xoc sshd[43210]: Invalid user '+marker+' from 192.0.2.10 port 4444'
    engine.run(['exec','-T','--user','999:999','siem','/var/ossec/framework/python/bin/python3','-c',
                'import socket,sys;s=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM);s.connect("/var/ossec/queue/sockets/queue");s.send(("1:xoc-native-probe:"+sys.argv[1]).encode())',line],compose=True)
    deadline=time.monotonic()+60;native_hits=[]
    while time.monotonic()<deadline:
        code,data=client.request('POST','/wazuh-alerts-4.x-*/_search',{'size':2,'query':{'match_phrase':{'full_log':line}}})
        native_hits=data.get('hits',{}).get('hits',[])
        if native_hits:break
        time.sleep(2)
    checks['stock_sshd_rule_indexes_original_alert']=code==200 and len(native_hits)==1 and native_hits[0]['_source']['rule']['id']=='5710' and 'event_id' not in native_hits[0]['_source']['xoc']
    # The ingestion service credential cannot read or delete search data.
    writer=Client(engine,plan['compose']['name'])
    checks['writer_cannot_read_events']=writer.request('POST','/xoc-events-*/_search',{'size':0})[0]==403
    checks['writer_cannot_read_native_alerts']=writer.request('POST','/wazuh-alerts-4.x-*/_search',{'size':0})[0]==403
    code,_,_=request('/siem/auth/logout','POST',{})
    checks['logout']=code in (200,302)
    code,_,_=request('/siem/api/saved_objects/_find?type=dashboard')
    checks['logout_revokes_browser_session']=code in (401,302)
    report={'status':'passed' if all(checks.values()) else 'failed','checks':checks,'scope':'Real HTTPS ingress -> fw -> IPS -> ModSecurity CRS -> authenticated Dashboards; C1 in Indexer.',
            'known_limitations':['ModSecurity 2.x #2807 rejects truncated JSON with HTTP 500 before phase 2; ordinary malformed JSON returns 400.']}
    Path('/var/lib/xocrange/siem-ui-acceptance.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    report=verify(Path(sys.argv[1]),sys.argv[2])
    print(json.dumps(report,indent=2))
    raise SystemExit(0 if report['status']=='passed' else 2)
