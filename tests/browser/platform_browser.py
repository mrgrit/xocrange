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
            page=browser.new_page();errors=[];page.on('pageerror',lambda error:errors.append(str(error)))
            page.goto(base+'/core/',wait_until='networkidle')
            checks['login_form']=page.locator('#login').is_visible()
            checks['readme_logo_loaded']=page.locator('header img').evaluate('(img)=>img.complete && img.naturalWidth>0')
            page.locator('#login-form [name=username]').fill('admin');page.locator('#login-form [name=password]').fill(c['password'])
            page.locator('#login-form button').click();page.locator('#account').wait_for(state='visible');page.locator('#device-list li').nth(2).wait_for()
            checks['admin_identity']=page.locator('#identity').inner_text()=='admin · admin'
            checks['three_device_policies']=page.locator('#device-list li').count()==3
            expect(page.locator('#audit')).to_contain_text('login')
            checks['accounts_and_audit_visible']=page.locator('#admin').is_visible() and 'login' in page.locator('#audit').inner_text()
            checks['siem_link_separate_account']='별도 Wazuh 계정' in page.locator('#siem-link').inner_text()
            page.reload(wait_until='networkidle');checks['reload_keeps_session']=page.locator('#account').is_visible()
            page.locator('#logout').click();page.locator('#login').wait_for(state='visible');checks['logout']=page.locator('#account').is_hidden()
            checks['no_javascript_errors']=not errors
            browser.close()
    finally:server.shutdown()
report={'status':'passed' if all(checks.values()) else 'failed','checks':checks};a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2));raise SystemExit(0 if report['status']=='passed' else 2)
