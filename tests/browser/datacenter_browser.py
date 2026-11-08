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
checks={};requests=[];errors=[];csp=[];svg_errors=[];avatar_layout={}
with Server(('127.0.0.1',0),Proxy) as server:
    threading.Thread(target=server.serve_forever,daemon=True).start()
    try:
        with sync_playwright() as pw:
            browser=pw.chromium.launch(headless=True,proxy={'server':'http://127.0.0.1:'+str(server.server_address[1])},args=['--ignore-certificate-errors-spki-list='+pin])
            page=browser.new_page(viewport={'width':1440,'height':1000},permissions=['clipboard-read','clipboard-write'])
            page.on('pageerror',lambda e:errors.append(str(e)))
            page.on('request',lambda r:requests.append(r.url))
            page.on('console',lambda m:svg_errors.append(m.text) if m.type=='error' and '<' in m.text and ('attribute' in m.text or 'SVG' in m.text) else None)
            page.on('console',lambda m:csp.append(m.text) if 'Content Security Policy' in m.text or 'violates the following' in m.text else None)
            page.goto(base+'/core/',wait_until='networkidle')
            page.locator('#login-form [name=username]').fill('admin');page.locator('#login-form [name=password]').fill(c['password']);page.locator('#login-form button').click()
            page.locator('#dc-stage').wait_for()
            checks['datacenter_is_default']=page.locator('#page-title').inner_text()=='데이터센터'
            checks['floor_directory_removed']=page.locator('.dc-floor-rail').count()==0
            checks['ten_admin_design_previews']=page.locator('.dc-level-preview').count()==10
            checks['gray_preview_keyboard_access']=page.locator('.dc-level-preview').evaluate_all("nodes=>nodes.every(n=>n.getAttribute('aria-disabled')==='false'&&n.getAttribute('tabindex')==='0'&&getComputedStyle(n).filter.includes('grayscale(1)'))")
            checks['all_floors_named']=all(t in page.locator('.dc-world-labels').text_content() for t in ('아카데미','Live Fire','가상회사'))
            avatar_layout=page.locator('[data-dc-floor]').evaluate_all("nodes=>Object.fromEntries(nodes.map(n=>[n.dataset.dcFloor,[...n.querySelectorAll('[data-worker-figure]')].map(a=>({id:a.dataset.workerFigure,position:a.dataset.avatarPosition,width:Number(a.dataset.avatarWidth)}))]))")
            counts={'B1':1,'1F':1,'2F':2,'3F':1,'4F':4,'5F':2,'XOC':2,'SITE':0,'6F':2,'7F':2,'8F':4}
            checks['original_and_extension_crew_counts']={f:len(v) for f,v in avatar_layout.items()}==counts
            original_positions={'facility-engineer':(4.8,3.5),'physical-security':(5.15,5.9),'network-engineer':(2.3,7),'systems-engineer':(10.3,7),'gpu-platform-engineer':(3.3,6.2),'service-desk':(2.38,3.65),'application-developer':(2.38,6.55),'compliance-auditor':(5.53,3.65),'ops-lead':(9.63,6.62),'skill-researcher':(2.58,4.55),'skill-evaluator':(8.33,4.55),'agent-supervisor':(2.68,4.8),'soc-analyst':(8.53,4.8)}
            original=[v for floor,rows in avatar_layout.items() if floor not in ('6F','7F','8F') for v in rows]
            checks['kt66_original_positions_preserved']=len(original)==13 and all(all(abs(float(actual)-expected)<1e-8 for actual,expected in zip(v['position'].split(','),(*original_positions[v['id']],.22))) for v in original)
            checks['kt66_avatar_size_preserved']=page.locator('[data-worker-figure]').evaluate_all("nodes=>nodes.every(n=>{const a=n.querySelector('svg');return Number(n.dataset.avatarWidth)===(a.dataset.avatarSeated==='true'?22:24)&&parseFloat(getComputedStyle(a).width)===Number(n.dataset.avatarWidth)&&getComputedStyle(a).stroke==='none'})")
            checks['helmet_and_suit_variants']=page.locator('[data-avatar-design]').evaluate_all("nodes=>new Set(nodes.map(n=>n.dataset.avatarRole)).size===17&&new Set(nodes.map(n=>n.dataset.avatarRank)).size===6")
            checks['no_tier_selector']=page.locator('#dc-stage select').count()==0
            checks['desktop_fills_view_without_page_scroll']=page.evaluate('document.documentElement.scrollHeight <= innerHeight+2')
            page.screenshot(path=str(a.output.with_suffix('.building.png')),full_page=True)
            for fid in ['B1','1F','3F','4F','5F','6F','7F','8F','XOC','SITE']:
                page.locator('[data-dc-floor="'+fid+'"]').focus();page.keyboard.press('Enter')
                expect(page.locator('#dc-stage')).to_have_attribute('data-mode','design')
                expect(page.locator('#dc-stage')).to_have_attribute('data-floor',fid)
                checks['admin_opens_'+fid]=page.locator('.dc-preview-badge').is_visible() and page.locator('[data-dc-asset],[data-dc-rack]').count()==0
                checks['preview_large_'+fid]=page.locator('[data-camera]').evaluate('n=>{const b=n.getBoundingClientRect(),s=n.ownerSVGElement.getBoundingClientRect();return b.width/s.width>.80||b.height/s.height>.80}')
                if fid in ('4F','6F','7F','8F'):
                    page.screenshot(path=str(a.output.with_suffix('.'+fid+'.png')),full_page=True)
                if fid=='6F':
                    checks['academy_is_content_library']=page.locator('[data-content-catalog]').count()==1 and page.locator('[data-content-thumbnail]').count()>=5
                    page.locator('[data-dc-design=workspace]').click();expect(page.locator('.cw-content-card')).to_have_count(6)
                    page.screenshot(path=str(a.output.with_suffix('.academy.png')),full_page=True)
                    before=len(requests)
                    page.locator('[data-cw-filter="방어·관제"]').click();expect(page.locator('.cw-content-card')).to_have_count(2)
                    page.locator('#cw-search').fill('헌팅');expect(page.locator('.cw-content-card')).to_have_count(1)
                    page.locator('.cw-content-card').click();expect(page.locator('.cw-content-detail')).to_be_visible()
                    page.locator('[data-cw-unit="워크북"]').click();expect(page.locator('#cw-unit-title')).to_have_text('워크북')
                    checks['catalog_filter_search_detail']=True
                    checks['catalog_preview_uses_no_backend']=len(requests)==before
                    page.locator('[data-cw-back]').click();page.locator('#cw-search').fill('');page.locator('[data-cw-filter="전체"]').click()
                if fid=='7F':
                    checks['live_fire_one_seat']=page.locator('[data-training-cockpit=single-seat]').count()==1
                    checks['four_training_panels']=page.locator('[data-mission-panel]').count()==4
                    page.locator('[data-dc-design=workspace]').click();expect(page.locator('.cw-flight-grid')).to_be_visible()
                    page.screenshot(path=str(a.output.with_suffix('.live-fire.png')),full_page=True)
                    before=len(requests)
                    page.locator('[data-cw-mode=DUEL]').click();page.locator('[data-cw-role=RED]').click();page.locator('[data-cw-scenario="1"]').click();page.locator('[data-cw-mission="2"]').click();page.locator('[data-cw-board="배틀별"]').click()
                    expect(page.locator('.cw-objective h3')).to_have_text('차단 근거 검증')
                    checks['mission_design_interactions']=page.locator('.cw-role-label').inner_text()=='RED' and page.locator('[data-cw-mode=DUEL]').get_attribute('aria-pressed')=='true'
                    checks['no_training_execution']=page.locator('.cw-mission-actions button:disabled').count()==3 and len(requests)==before
                    checks['training_dashboard_sections']=all(t in page.locator('.commercial-workspace').inner_text() for t in ('과정별 진척도','전체 리더보드','나의 레벨','AI 피드백'))
                    for width,height in [(1280,800),(430,900),(320,740)]:
                        page.set_viewport_size({'width':width,'height':height});page.wait_for_timeout(120)
                        checks['live_fire_'+str(width)+'_no_overflow']=page.evaluate('document.documentElement.scrollWidth<=innerWidth')
                    page.set_viewport_size({'width':1440,'height':1000})
                if fid=='8F':checks['company_operations_rack']=page.locator('[data-company-rack=R-8F-01]').count()==1
                page.locator('[data-dc-mode=building]').click();page.locator('.dc-level-active').wait_for()
            page.locator('.dc-level-active').focus();page.keyboard.press('Enter');page.locator('.dc-interior').wait_for()
            checks['keyboard_enters_second_floor']=page.locator('#dc-stage').get_attribute('data-mode')=='floor'
            data=page.evaluate("async()=> (await (await fetch('/core/api/datacenter')).json())")
            assets=data['assets'];racks=data['racks']
            checks['original_two_racks']=set(page.locator('.dc-interior g[data-dc-rack]').evaluate_all('nodes=>nodes.map(n=>n.dataset.dcRack)'))=={'R-2F-01','R-2F-02'}
            checks['rack_buttons_match_registry']=page.locator('.dc-service-chip').count()==len(racks)==2
            checks['devices_require_rack_selection']=page.locator('#dc-inspector').is_hidden() and page.locator('[data-dc-asset]').count()==0
            fw=next(a for a in assets if a['service']=='fw')
            rack=page.locator('.dc-interior g[data-dc-rack="'+fw['rack_id']+'"]')
            rack.focus();page.keyboard.press('Space');expect(page.locator('.dc-rack-list')).to_be_visible()
            checks['keyboard_opens_rack_inventory']=set(page.locator('.dc-rack-list button').evaluate_all('nodes=>nodes.map(n=>n.dataset.dcAsset)'))=={a['asset_id'] for a in assets if a['rack_id']==fw['rack_id']}
            page.screenshot(path=str(a.output.with_suffix('.rack.png')),full_page=True)
            page.locator('[data-dc-asset="'+fw['asset_id']+'"]').focus();page.keyboard.press('Enter')
            expect(page.locator('#dc-inspector .dc-service-name')).to_have_text('fw')
            checks['keyboard_selects_actual_device']=page.locator('.dc-device-description').inner_text()==fw['description']
            checks['ssh_targets_deployed_host']=page.locator('#dc-ssh-command').input_value()=='ssh ccc@'+host
            page.locator('[data-dc-copy=ssh]').click()
            checks['ssh_clipboard_matches_display']=page.evaluate('navigator.clipboard.readText()')==page.locator('#dc-ssh-command').input_value()
            page.locator('#dc-ssh-user').fill('-oProxyCommand=id')
            checks['ssh_options_rejected']=page.locator('[data-dc-copy=ssh]').is_disabled()
            page.locator('#dc-ssh-user').fill('ccc');page.locator('#dc-ssh-port').fill('2222')
            checks['custom_ssh_port']=page.locator('#dc-ssh-command').input_value()=='ssh -p 2222 ccc@'+host
            page.locator('#dc-ssh-port').fill('22')
            page.locator('[data-dc-copy=shell]').click()
            checks['shell_clipboard_matches_registered_service']=page.evaluate('navigator.clipboard.readText()')==fw['access']['shell_command']
            page.locator('#dc-inspector').evaluate('n=>n.scrollTop=0')
            page.locator('[data-dc-zoom=in]').click();expect(page.locator('#dc-zoom-value')).to_have_text('115%')
            with page.expect_response(lambda r:r.url.endswith('/core/api/datacenter'),timeout=25000):
                page.wait_for_timeout(17000)
            expect(page.locator('#dc-zoom-value')).to_have_text('115%');expect(page.locator('#dc-inspector')).to_contain_text('방화벽')
            checks['automatic_refresh_preserves_selection_and_camera']=page.locator('#dc-stage').get_attribute('data-mode')=='floor'
            checks['real_observation_visible']='관측 연결' in page.locator('.dc-status').inner_text()
            page.locator('[data-dc-zoom=reset]').click();page.screenshot(path=str(a.output.with_suffix('.detail.png')),full_page=True)
            page.locator('#dc-inspector').evaluate('n=>n.scrollTop=n.scrollHeight')
            page.screenshot(path=str(a.output.with_suffix('.access.png')),full_page=True)
            page.locator('[data-dc-back]').click();expect(page.locator('.dc-rack-list')).to_be_visible()
            checks['back_restores_rack_inventory']=page.locator('.dc-rack-list button').count()==len(next(r['asset_ids'] for r in racks if r['id']==fw['rack_id']))
            no_console=next(a for a in assets if a['rack_id']==fw['rack_id'] and not a['web_console'])
            page.locator('[data-dc-asset="'+no_console['asset_id']+'"]').click()
            checks['no_console_device_has_no_link']=page.locator('#dc-inspector a.workspace-link').count()==0
            page.locator('[data-dc-back]').click();page.locator('[data-dc-asset="'+fw['asset_id']+'"]').click()
            page.locator('#dc-inspector a.workspace-link').click();page.locator('#tabs').wait_for(state='visible')
            checks['device_opens_existing_console']=page.locator('#page-title').inner_text()=='방화벽 정책'
            page.locator('[data-nav=datacenter]').click();page.locator('.dc-interior').wait_for()
            page.locator('.dc-service-chip[data-dc-rack=R-2F-02]').click()
            dashboard=next(a for a in assets if a['service']=='dashboard')
            page.locator('[data-dc-asset="'+dashboard['asset_id']+'"]').click()
            link=page.locator('#dc-inspector a.workspace-link')
            checks['siem_device_link_uses_new_tab']=link.get_attribute('href')=='/siem/' and link.get_attribute('target')=='_blank' and 'noopener' in link.get_attribute('rel')
            page.locator('[data-dc-close]').click();page.screenshot(path=str(a.output.with_suffix('.floor.png')),full_page=True)
            page.locator('[data-dc-fullscreen]').click()
            expect(page.locator('#dc-stage:fullscreen')).to_be_visible()
            checks['fullscreen_enter']=page.evaluate('document.fullscreenElement?.id')=='dc-stage'
            page.locator('[data-dc-fullscreen]').click();expect(page.locator('#dc-stage:fullscreen')).to_have_count(0);checks['fullscreen_exit']=page.evaluate('document.fullscreenElement===null')
            page.locator('[data-dc-mode=building]').click()
            box=page.locator('#dc-scene').bounding_box();before=page.locator('[data-camera]').get_attribute('transform')
            page.mouse.move(box['x']+12,box['y']+70);page.mouse.down();page.mouse.move(box['x']+50,box['y']+90,steps=5);page.mouse.up()
            checks['camera_pan']=page.locator('[data-camera]').get_attribute('transform')!=before
            page.locator('[data-dc-zoom=reset]').click()
            page.emulate_media(reduced_motion='reduce')
            checks['reduced_motion']=page.evaluate("matchMedia('(prefers-reduced-motion: reduce)').matches && Array.from(document.querySelectorAll('#dc-stage *')).every(n=>getComputedStyle(n).animationName==='none')")
            for label,width,height in [('laptop',1280,800),('mobile',430,900),('small_mobile',320,740)]:
                page.set_viewport_size({'width':width,'height':height});page.wait_for_timeout(100)
                checks[label+'_no_horizontal_overflow']=page.evaluate('document.documentElement.scrollWidth <= innerWidth')
                checks[label+'_floor_labels_not_clipped']=page.locator('.dc-world-labels g').evaluate_all('nodes=>nodes.length===11&&nodes.every(n=>{const b=n.getBoundingClientRect();return b.left>=0&&b.right<=innerWidth})')
                checks[label+'_active_floor_accessible']=page.locator('.dc-level-active').is_visible()
                if label=='laptop':checks['laptop_no_page_scroll']=page.evaluate('document.documentElement.scrollHeight <= innerHeight+2')
                page.screenshot(path=str(a.output.with_suffix('.'+label+'.png')),full_page=True)
            page.locator('[data-dc-mode=floor]').click();page.locator('.dc-interior').wait_for()
            page.locator('.dc-service-chip').first.click();page.locator('.dc-rack-list button').first.click();expect(page.locator('#dc-inspector')).to_be_visible()
            checks['small_mobile_detail_no_overflow']=page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            checks['no_defensive_copy']=all(t not in page.locator('#dc-stage').inner_text() for t in ('실제 랙 위치','논리 배치','의미하지 않습니다'))
            checks['no_paid_endpoints_or_external_assets']=not any(any(t in u for t in ('/envsim','/injector','/agents','/roster')) or not u.startswith(base) for u in requests)
            async_contract=dict(data,preview_floors=[])
            page.route('**/core/api/datacenter',lambda route:route.fulfill(json=async_contract))
            page.reload(wait_until='networkidle');page.locator('.dc-level-active').wait_for()
            checks['nonadmin_contract_keeps_ten_floors_locked']=page.locator('.dc-level-locked').count()==10 and page.locator('.dc-level-preview').count()==0
            checks['nonadmin_locked_svg_inert']=page.locator('.dc-level-locked').evaluate_all("nodes=>nodes.every(n=>n.getAttribute('aria-disabled')==='true'&&!n.hasAttribute('tabindex')&&getComputedStyle(n).pointerEvents==='none')")
            before=len(requests)
            page.evaluate("()=>document.querySelectorAll('.dc-level-locked').forEach(n=>n.dispatchEvent(new MouseEvent('click',{bubbles:true})))")
            checks['nonadmin_click_cannot_request_preview']=not any('/datacenter/design/' in u or '/datacenter/floors/' in u for u in requests[before:])
            page.unroute('**/core/api/datacenter')
            page.locator('#logout').click();page.locator('#login').wait_for(state='visible')
            checks['logout_hides_scene']=page.locator('#account').is_hidden()
            checks['no_invalid_svg_attributes']=not svg_errors;checks['no_javascript_errors']=not errors;checks['no_csp_violations']=not csp
            browser.close()
    finally:server.shutdown()
report={'status':'passed' if all(checks.values()) else 'failed','checks':checks,'javascript_errors':errors,'csp_violations':csp,'svg_errors':svg_errors,'avatar_layout':avatar_layout}
a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2));raise SystemExit(report['status']!='passed')
