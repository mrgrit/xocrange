#!/usr/bin/env python3
"""Read-only browser acceptance through a local SSH forward, preserving Origin."""
import argparse,base64,hashlib,json,select,socket,socketserver,ssl,subprocess,threading
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

p=argparse.ArgumentParser();p.add_argument('--credentials',type=Path,required=True);p.add_argument('--ca',type=Path,required=True);p.add_argument('--certificate',type=Path,required=True);p.add_argument('--forward-port',type=int,default=8443);p.add_argument('--output',type=Path,required=True);p.add_argument('--reduced',action='store_true');a=p.parse_args()
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
checks={};requests=[];errors=[]
with Server(('127.0.0.1',0),Proxy) as server:
    threading.Thread(target=server.serve_forever,daemon=True).start()
    try:
        with sync_playwright() as pw:
            browser=pw.chromium.launch(headless=True,proxy={'server':'http://127.0.0.1:'+str(server.server_address[1])},args=['--ignore-certificate-errors-spki-list='+pin])
            context=browser.new_context(viewport={'width':1440,'height':1000});page=context.new_page()
            page.on('pageerror',lambda error:errors.append(str(error)))
            page.on('request',lambda request:requests.append(request.url))
            page.goto(base+'/core/',wait_until='networkidle')
            page.locator('#login-form [name=username]').fill('admin');page.locator('#login-form [name=password]').fill(c['password'])
            page.locator('#login-form button').click();page.locator('#account').wait_for(state='visible')
            if a.reduced:
                page.locator('#tabs').wait_for(state='visible')
                checks['optional_navigation_hidden']=all(page.locator('[data-nav='+v+']').count()==0 or page.locator('[data-nav='+v+']').is_hidden() for v in ('datacenter','portal','noc','academy','ips'))
                checks['siem_hidden']=page.locator('#siem-link').is_hidden()
                for view in ('datacenter','portal','noc','academy'):
                    page.goto(base+'/core/#'+view)
                    expect(page.locator('#system-view')).to_contain_text('설치되지 않은 기능')
                checks['disabled_features_make_no_requests']=not any(any('/core/api/'+path in u for path in ('datacenter','registry','noc','library','console/ips')) or '/siem/' in u for u in requests)
            else:
                page.locator('#dc-stage').wait_for()
                checks['datacenter_default']=page.locator('#page-title').inner_text()=='데이터센터'
                page.locator('[data-nav=portal]').click()
                page.locator('#inventory-rows tr').nth(9).wait_for()
                checks['portal_available']=page.locator('#page-title').inner_text()=='운영 개요'
                checks['installed_inventory_visible']=page.locator('#inventory-rows tr').count()==10
                page.screenshot(path=str(a.output.with_suffix('.portal.png')),full_page=True)
                page.locator('#inventory-search').fill('fw')
                checks['service_search']=page.locator('#inventory-rows tr').count()==1
                page.locator('#inventory-search').fill('')
                page.locator('[data-nav=noc]').click();page.locator('.noc-floor').wait_for()
                checks['second_floor_only']=page.locator('.floor-number').all_text_contents()==['2F']
                checks['four_security_stages']=page.locator('.noc-path .noc-asset').count()==4
                checks['no_simulated_facility_metrics']=not any(t in page.locator('#system-view').inner_text() for t in ('°C',' kW','AI 근무자'))
                page.locator('.noc-path .noc-asset').nth(1).click();expect(page.locator('#asset-detail')).to_contain_text('방화벽')
                checks['asset_detail_has_observation']=page.locator('#asset-detail .metric-label',has_text='마지막 관측').is_visible()
                page.screenshot(path=str(a.output.with_suffix('.noc.png')),full_page=True)
                page.locator('#asset-detail a.workspace-link').click();page.locator('#tabs [data-tab=policies]').wait_for()
                checks['asset_links_to_console']=page.locator('#page-title').inner_text()=='방화벽 정책'
                page.locator('[data-nav=academy]').click();page.locator('.guide-card').nth(3).wait_for()
                checks['four_bundled_guides']=page.locator('.guide-card').count()==4
                page.locator('.guide-card').nth(1).click();page.locator('.reading').wait_for()
                checks['readable_article']=page.locator('.reading h2').inner_text()=='보안 트래픽 경로 이해하기'
                page.screenshot(path=str(a.output.with_suffix('.reader.png')),full_page=True)
                page.locator('[data-nav=portal]').click();page.locator('#inventory-rows').wait_for()
                with page.expect_popup() as opened:page.locator('#siem-link').click()
                popup=opened.value;popup.locator('input[type=password]').wait_for(timeout=60000)
                checks['siem_still_opens_separately']=popup is not page and page.locator('#account').is_visible();popup.close()
                checks['no_paid_dependencies_requested']=not any(any(token in u for token in ('/envsim','/injector','/agents','/roster')) for u in requests)
                page.set_viewport_size({'width':430,'height':900})
                for view in ('datacenter','portal','noc','academy'):
                    page.locator('[data-nav='+view+']').click()
                    page.wait_for_timeout(500)
                    checks['mobile_'+view+'_no_overflow']=page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
                    checks['mobile_'+view+'_nav_accessible']=page.locator('[data-nav='+view+']').is_visible()
                page.locator('[data-nav=noc]').click();page.locator('.noc-floor').wait_for();page.screenshot(path=str(a.output.with_suffix('.mobile.png')),full_page=True)
            page.locator('#logout').click();page.locator('#login').wait_for(state='visible');checks['logout']=page.locator('#account').is_hidden()
            checks['no_javascript_errors']=not errors
            browser.close()
    finally:server.shutdown()
report={'status':'passed' if all(checks.values()) else 'failed','checks':checks}
a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2));raise SystemExit(report['status']!='passed')
