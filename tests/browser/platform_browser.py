#!/usr/bin/env python3
"""Read-only browser acceptance through a local SSH forward, preserving Origin."""
import argparse,base64,hashlib,json,select,socket,socketserver,ssl,subprocess,threading
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

p=argparse.ArgumentParser();p.add_argument('--credentials',type=Path,required=True);p.add_argument('--ca',type=Path,required=True);p.add_argument('--certificate',type=Path,required=True);p.add_argument('--forward-port',type=int,default=8443);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
if a.credentials.is_symlink() or a.credentials.stat().st_mode&0o077:raise SystemExit('Private credentials required')
c=json.loads(a.credentials.read_text());host=c['public_host'];base='https://'+host
# Normal hostname/CA verification precedes a leaf-specific Chromium test pin.
with socket.create_connection(('127.0.0.1',a.forward_port),timeout=10) as raw:
    with ssl.create_default_context(cafile=str(a.ca)).wrap_socket(raw,server_hostname=host):pass
public=subprocess.check_output(['openssl','x509','-in',str(a.certificate),'-pubkey','-noout'])
der=subprocess.run(['openssl','pkey','-pubin','-outform','DER'],input=public,capture_output=True,check=True).stdout
pin=base64.b64encode(hashlib.sha256(der).digest()).decode()
class Proxy(socketserver.BaseRequestHandler):
    def handle(self):
        data=b''
        while b'\r\n\r\n' not in data and len(data)<8192:
            chunk=self.request.recv(1024)
            if not chunk:return
            data+=chunk
        if data.split(b'\r\n',1)[0] != ('CONNECT '+host+':443 HTTP/1.1').encode():
            self.request.sendall(b'HTTP/1.1 403 Forbidden\r\n\r\n');return
        with socket.create_connection(('127.0.0.1',a.forward_port)) as target:
            self.request.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            peers=[self.request,target]
            while True:
                ready,_,_=select.select(peers,[],[],30)
                if not ready:return
                for peer in ready:
                    chunk=peer.recv(65536)
                    if not chunk:return
                    (target if peer is self.request else self.request).sendall(chunk)
class Server(socketserver.ThreadingTCPServer):daemon_threads=True
checks={}
with Server(('127.0.0.1',0),Proxy) as server:
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        with sync_playwright() as pw:
            browser=pw.chromium.launch(headless=True,proxy={'server':'http://127.0.0.1:'+str(server.server_address[1])},args=['--ignore-certificate-errors-spki-list='+pin])
            page=browser.new_page(viewport={"width":1500,"height":960});errors=[];page.on('pageerror',lambda error:errors.append(str(error)))
            page.goto(base+'/core/',wait_until='networkidle')
            checks['login_form']=page.locator('#login').is_visible()
            checks['readme_logo_loaded']=page.locator('#login img').evaluate('(img)=>img.complete && img.naturalWidth>0')
            page.locator('#login-form [name=username]').fill('admin');page.locator('#login-form [name=password]').fill(c['password'])
            page.locator('#login-form button').click();page.locator('#account').wait_for(state='visible')
            checks['admin_identity']=page.locator('#identity').inner_text()=='admin · 관리자'
            page.locator('[data-nav=fw]').click();page.locator('#tabs [data-tab=policies]').wait_for()
            expect(page.locator('#device-content')).to_contain_text('FORWARD')
            checks['forward_default_policy_view']=page.locator('#tabs [data-tab=policies]').get_attribute('aria-selected')=='true'
            checks['system_rules_protected']='시스템 경로 정책' in page.locator('#device-content').inner_text()
            page.screenshot(path=str(a.output.with_suffix('.desktop.png')),full_page=True)
            page.locator('[data-action=new]').click();page.locator('#policy-form [name=name]').fill('웹 서비스 허용')
            page.locator('#policy-form [name=f_dport]').fill('8080');page.screenshot(path=str(a.output.with_suffix('.fw-editor.png')),full_page=False);page.locator('#validate-button').click()
            page.locator('#review').wait_for(state='visible')
            checks['editor_real_configtest']='장비 설정 검증 통과' in page.locator('#review').inner_text()
            checks['preview_does_not_require_write_unlock']=page.locator('#apply').is_disabled()
            page.screenshot(path=str(a.output.with_suffix('.review.png')),full_page=False)
            page.locator('#review [data-close=review]').first.click()
            page.locator('[data-tab=ruleset]').click();expect(page.locator('#full-rules')).to_contain_text('xoc_fw')
            checks['whole_ruleset_separate_tab']=page.locator('#policy-table').count()==0
            page.locator('[data-tab=objects]').click();expect(page.locator('#device-content')).to_contain_text('주소·서비스 객체')
            page.locator('[data-tab=nat]').click();expect(page.locator('#device-content')).to_contain_text('주소 변환 정책')
            checks['objects_and_nat_separate']=True
            for device in ('ips','waf'):
                page.locator('[data-nav='+device+']').click();page.locator('[data-action=new]').wait_for()
                expect(page.locator('#device-summary')).to_contain_text('연결됨')
                page.locator('[data-action=new]').click();checks[device+'_editor']=page.locator('#editor').is_visible()
                page.screenshot(path=str(a.output.with_suffix('.'+device+'-editor.png')),full_page=False)
                page.locator('#editor [data-close=editor]').first.click()
            page.locator('[data-nav=access]').click();page.locator('#device-list li').nth(2).wait_for()
            checks['three_device_policies']=page.locator('#device-list li').count()==3
            page.locator('[data-nav=users]').click();page.locator('#users').wait_for()
            checks['accounts_table']=page.locator('#users').is_visible()
            page.locator('[data-nav=audit]').click();expect(page.locator('#audit')).to_contain_text('login')
            checks['audit_table']=page.locator('#audit').is_visible()
            checks['siem_link_separate_account']='별도 Wazuh 계정' in page.locator('#siem-link').get_attribute('title')
            page.reload(wait_until='networkidle');checks['reload_keeps_session']=page.locator('#account').is_visible()
            page.locator('[data-nav=fw]').click();page.locator('#tabs [data-tab=policies]').wait_for()
            page.set_viewport_size({'width':430,'height':900});page.screenshot(path=str(a.output.with_suffix('.mobile.png')),full_page=True)
            checks['mobile_no_page_overflow']=page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
            page.locator('#logout').click();page.locator('#login').wait_for(state='visible');checks['logout']=page.locator('#account').is_hidden()
            checks['no_javascript_errors']=not errors
            browser.close()
    finally:server.shutdown()
report={'status':'passed' if all(checks.values()) else 'failed','checks':checks};a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2));raise SystemExit(0 if report['status']=='passed' else 2)
