#!/usr/bin/env python3
"""Exercise editable reports and persistence. Refuses to alter existing mission records."""
import argparse,json,base64,traceback
from pathlib import Path
from playwright.sync_api import sync_playwright,expect
p=argparse.ArgumentParser();p.add_argument('--url',required=True);p.add_argument('--credentials',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--proxy');p.add_argument('--ignore-https-errors',action='store_true');a=p.parse_args()
assert not a.credentials.is_symlink() and not a.credentials.stat().st_mode&0o077
creds=json.loads(a.credentials.read_text());origin=a.url.rstrip('/');out=a.output;out.mkdir(mode=0o700,parents=True,exist_ok=True)
checks={};errors=[];created=[];cid='wazuh-threat-hunting';sid='xoc-web-01';mid=sid+'-red-01';second=sid+'-red-02';route='#academy/scenario/'+sid+'/'+mid
try:
 with sync_playwright() as pw:
  opts={'ignore_https_errors':a.ignore_https_errors,'viewport':{'width':1680,'height':1050},'permissions':['clipboard-read','clipboard-write']}
  if a.proxy:opts['proxy']={'server':a.proxy}
  browser=pw.chromium.launch();context=browser.new_context(**opts);page=context.new_page();page.on('pageerror',lambda e:errors.append(str(e)))
  def created_response(r):
   if r.request.method=='POST' and r.url.endswith('/core/api/academy/records') and r.status==201:
    created.append(r.json()['id']);(out/'created-records.json').write_text(json.dumps(created))
  page.on('response',created_response)
  def login():
   page.locator('#login-form [name=username]').fill('admin');page.locator('#login-form [name=password]').fill(creds.get('admin',creds.get('password')));page.locator('#login-form button').click();expect(page.locator('[data-lf-field]')).to_have_count(3,timeout=30000)
  def rows():return page.request.get(origin+f'/core/api/academy/scenarios/{cid}/{sid}/records').json()['records']
  def saved():expect(page.locator('#lf-status')).to_contain_text('저장됨',timeout=20000)
  page.goto(origin+'/core/'+route);login();assert not any(r['mission'] in (mid,second) for r in rows()),'Use missions without existing learner records.'
  checks['three_inputs_enabled']=page.locator('[data-lf-field]').evaluate_all('xs=>xs.every(x=>!x.disabled)') and page.locator('[data-lf-save=complete]').is_enabled()
  checks['labels']=all(x in page.locator('#lf-report').inner_text() for x in ('학습자 시도','시스템 반응','학습자의 해석'))
  attempt='curl --get http://training.invalid/ --data-urlencode "id=1\' OR \'1\'=\'1"\n시도 1: HTTP 요청과 태그 확인'
  page.locator('#lf-input').fill(attempt);saved();checks['partial_autosave']=rows()[0]['input']==attempt
  page.locator('[data-lf-save=complete]').click();expect(page.locator('#lf-status')).to_contain_text('모두 기록',timeout=20000);checks['registration_requires_three_parts']=rows()[0]['status']=='draft'
  output='<script>window.livefireAttack=1</script>\n'+('2026-11-08 HTTP 403 — 전체 관측 로그\n'*1400)
  interpretation='실행 결과와 같은 시각의 차단 로그를 연결했다. 침해 성공 여부는 확인하지 못했다.'
  page.locator('#lf-output').fill(output);page.locator('#lf-interpretation').fill(interpretation);saved();checks['long_literal_output_saved']=rows()[0]['output']==output
  page.reload();expect(page.locator('#lf-input')).to_have_value(attempt);expect(page.locator('#lf-output')).to_have_value(output);expect(page.locator('#lf-interpretation')).to_have_value(interpretation);checks['reload_restores_all_fields']=True
  blob=page.evaluate('''()=>{const c=document.createElement('canvas');c.width=400;c.height=160;const x=c.getContext('2d');x.fillStyle='#24242b';x.fillRect(0,0,400,160);x.fillStyle='white';x.font='20px sans-serif';x.fillText('Live Fire / HTTP 403',25,80);return c.toDataURL('image/png').split(',')[1]}''')
  page.locator('#lf-images').set_input_files([{'name':f'livefire-evidence-{i}.png','mimeType':'image/png','buffer':base64.b64decode(blob)} for i in range(4)])
  expect(page.locator('.lf-evidence img')).to_have_count(4,timeout=30000);checks['four_captures_saved']=len(rows()[0]['images'])==4
  page.evaluate('''async()=>{const c=document.createElement('canvas');c.width=320;c.height=140;const x=c.getContext('2d');x.fillStyle='navy';x.fillRect(0,0,320,140);const b=await new Promise(r=>c.toBlob(r,'image/png'));await navigator.clipboard.write([new ClipboardItem({'image/png':b})]);}''')
  page.locator('#lf-output').focus();page.keyboard.press('Control+V');expect(page.locator('.lf-evidence img')).to_have_count(5,timeout=15000);checks['clipboard_capture_saved']=True
  page.locator('[data-lf-save=complete]').click();expect(page.locator('#lf-status')).to_contain_text('등록됨',timeout=20000);registered=next(r for r in rows() if r['mission']==mid);rid=registered['id'];checks['registration_persisted']=registered['status']=='complete' and len(registered['versions'])>=1 and not registered['evaluation']['ai_available']
  registered_version=registered['revision'];page.locator('#lf-report').screenshot(path=str(out/'report.png'))
  # Edit and immediately switch missions: flushing must finish without another click.
  page.locator('#lf-interpretation').fill(interpretation+' 추가 관측 중.');page.locator('[data-ac-training="'+second+'"]').click();expect(page.locator('#lf-input')).to_have_value('');page.locator('#lf-input').fill('다음 미션의 시도 기록');saved()
  page.locator('[data-ac-training="'+mid+'"]').click();expect(page.locator('#lf-interpretation')).to_have_value(interpretation+' 추가 관측 중.');checks['mission_switch_preserves_drafts']=True
  page.locator('#lf-record-link').click();expect(page.locator('.ac-record-detail')).to_be_visible();checks['record_view_has_three_sections']=all(x in page.locator('.ac-record-detail').inner_text() for x in ('학습자 시도','시스템 반응','학습자의 해석'));checks['script_remains_literal']=page.evaluate('window.livefireAttack===undefined') and '<script>' in page.locator('.ac-saved-text').nth(1).inner_text()
  page.locator('#ac-version').select_option(str(registered_version));expect(page.locator('.ac-saved-text').last).to_have_text(interpretation);checks['registered_snapshot_immutable']=page.locator('.ac-evidence-list img').count()==5
  page.locator('a[href="'+route+'"]').click();expect(page.locator('#lf-input')).to_have_value(attempt);checks['continue_record_route']=True
  for width in (1024,430):
   page.set_viewport_size({'width':width,'height':900});checks['no_overflow_'+str(width)]=page.evaluate('document.documentElement.scrollWidth<=innerWidth+1');page.screenshot(path=str(out/f'mission-{width}.png'),full_page=True)
  page.set_viewport_size({'width':1680,'height':1050})
  # A second tab cannot overwrite a newer draft. Keep the stale local text visible.
  tab=context.new_page();tab.goto(origin+'/core/'+route);expect(tab.locator('#lf-input')).to_have_value(attempt)
  page.locator('#lf-input').fill(attempt+'\n첫 탭 수정');saved();tab.locator('#lf-input').fill('다른 탭의 오래된 수정');expect(tab.locator('#lf-status')).to_contain_text('저장 실패',timeout=20000)
  checks['stale_write_keeps_local_text']=tab.locator('#lf-input').input_value()=='다른 탭의 오래된 수정' and next(r for r in rows() if r['mission']==mid)['input']==attempt+'\n첫 탭 수정';tab.close()
  page.locator('#lf-interpretation').fill(interpretation+' 로그아웃 직전 수정');page.locator('#logout').click();expect(page.locator('#login')).to_be_visible(timeout=15000);login();expect(page.locator('#lf-interpretation')).to_have_value(interpretation+' 로그아웃 직전 수정');checks['logout_flush_and_login_restore']=True
  checks['no_javascript_errors']=not errors;browser.close()
except Exception:
 traceback.print_exc();raise
finally:
 (out/'livefire-browser.json').write_text(json.dumps({'checks':checks,'errors':errors,'created_records':created},ensure_ascii=False,indent=2)+'\n')
 print(json.dumps({'checks':len(checks),'failed':[k for k,v in checks.items() if not v]}))
assert checks and all(checks.values())
