#!/usr/bin/env python3
"""Write an Academy test notebook through a real browser on an empty test account.

Creates one Discover notebook. The exact IDs are saved in created-records.json
for inspection and operator cleanup; preexisting notebooks are never edited.
"""
import argparse,json,traceback
from pathlib import Path
from playwright.sync_api import sync_playwright,expect
p=argparse.ArgumentParser()
p.add_argument('--url',required=True)
p.add_argument('--credentials',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
p.add_argument('--proxy')
p.add_argument('--ignore-https-errors',action='store_true')
args=p.parse_args()
if args.credentials.is_symlink() or args.credentials.stat().st_mode&0o077:
    raise SystemExit('Credentials must be a private regular file.')
creds=json.loads(args.credentials.read_text())
if 'admin' not in creds:creds['admin']=creds['password']
origin=args.url.rstrip('/');out=args.output;out.mkdir(parents=True,exist_ok=True,mode=0o700)
checks={};errors=[];created=[]
try:
 with sync_playwright() as p:
  browser=p.chromium.launch();opts={'ignore_https_errors':args.ignore_https_errors,'viewport':{'width':1680,'height':1050},'permissions':['clipboard-read','clipboard-write']}
  if args.proxy:opts['proxy']={'server':args.proxy}
  context=browser.new_context(**opts);page=context.new_page();page.on('pageerror',lambda e:errors.append(str(e)))
  def response(r):
   if r.request.method=='POST' and r.url.endswith('/core/api/academy/records') and r.status==201:created.append(r.json()['id']);(out/'created-records.json').write_text(json.dumps(created))
  page.on('response',response)
  page.goto(origin+'/core/#datacenter');page.locator('#login-form input[name=username]').fill('admin');page.locator('#login-form input[name=password]').fill(creds['admin']);page.locator('#login-form button').click()
  expect(page.locator('[data-dc-floor="6F"]')).to_be_visible(timeout=30000)
  checks['building_has_no_separate_learning_panel']=page.locator('#dc-learning').count()==0
  page.locator('[data-dc-floor="6F"]').click();expect(page.locator('#dc-stage')).to_have_attribute('data-mode','learning')
  expect(page.locator('.al-card')).to_have_count(24);checks['floor6_actual_catalog']=page.locator('a.al-card').count()==1;page.locator('[data-dc-design=space]').click();checks['floor6_actual_content_inside_displays']='24개 콘텐츠' in page.locator('.dc-room-screen').first.text_content()
  checks['floor6_large_display_type']=page.locator('.dc-room-screen text').first.evaluate('e=>parseFloat(getComputedStyle(e).fontSize)*Math.hypot(e.getScreenCTM().c,e.getScreenCTM().d)>=16')
  page.locator('[data-dc-learning-route="#academy/course/wazuh-threat-hunting"]').click();expect(page.locator('.ac-lesson-card').first).to_be_visible();checks['floor6_screen_opens_course']=True
  page.locator('a.ac-lesson-card[href$="/discover"]').click();expect(page.locator('#ac-notebook')).to_be_visible()
  checks['outline_hidden_initially']=not page.locator('.ac-outline').is_visible()
  checks['compact_header']=page.locator('.ac-reader').bounding_box()['y']<=115
  checks['reading_uses_viewport']=page.locator('.ac-reader').bounding_box()['height']>=850
  checks['body_font_17px']=page.locator('.ac-explanation').evaluate('e=>parseFloat(getComputedStyle(e).fontSize)>=17')
  checks['markdown_bold_rendered']=page.locator('.ac-explanation strong').count()>0
  checks['no_raw_markdown_in_prose']=page.locator('.ac-explanation').evaluate("e=>![...e.querySelectorAll('p,li')].some(p=>/\\*\\*[^*]+\\*\\*/.test(p.textContent))")
  page.locator('.ac-reader figure img').first.scroll_into_view_if_needed();expect(page.locator('.ac-reader figure img').first).to_have_js_property('complete',True);checks['reader_image_loaded']=page.locator('.ac-reader figure img').first.evaluate('e=>e.naturalWidth>0');
  checks['reader_images_bounded']=page.locator('.ac-reader figure img').evaluate_all('xs=>xs.length>0&&xs.every(e=>e.getBoundingClientRect().height<=281&&e.getBoundingClientRect().width<=501)')
  page.locator('[data-ac-outline]').click();expect(page.locator('#ac-outline-dialog')).to_be_visible();checks['outline_all_36_lessons']=page.locator('#ac-outline-dialog nav a').count()==36;page.keyboard.press('Escape');checks['outline_escape_closes']=not page.locator('#ac-outline-dialog').is_visible()
  assert page.request.get(origin+'/core/api/academy/lessons/wazuh-threat-hunting/discover').json()['notebook'] is None, 'Use an empty test account; an existing Discover notebook must not be overwritten.'
  first=page.locator('[data-nb-text]').first;first.fill('Discover 실습 기록\n검색 기간을 설정하고 필터를 비교했다.\n<script>window.notebookAttack=1</script>')
  expect(page.locator('#nb-status')).to_contain_text('저장됨',timeout=15000);checks['autosave_without_button']=True
  page.reload();expect(page.locator('[data-nb-text]').first).to_contain_text('검색 기간을 설정');checks['reload_restores_draft']=True
  page.locator('[data-nb-add=heading]').click();page.locator('.nb-heading textarea').fill('검색 조건과 관측 결과')
  page.locator('[data-nb-add=code]').click();long_log='curl --get https://training.invalid/ --data-urlencode "id=1\' OR \'1\'=\'1"\n'+('2026-11-08 HTTP 403 — 전체 출력과 원본 로그\n'*1200)
  page.locator('.nb-code textarea').fill(long_log);expect(page.locator('#nb-status')).to_contain_text('저장됨',timeout=15000);checks['long_multiline_log_saved']=True
  # Four image files exceed the old three-image record limit, then paste another.
  import base64
  # Browser generates readable evidence images instead of relying on fixture codecs.
  blob=page.evaluate('''async()=>{const c=document.createElement('canvas');c.width=640;c.height=240;const x=c.getContext('2d');x.fillStyle='#2c203a';x.fillRect(0,0,640,240);x.fillStyle='#67e5db';x.font='22px monospace';x.fillText('Discover / evidence sample',30,90);x.fillText('HTTP 403 | xoc-web-02',30,140);return c.toDataURL('image/png').split(',')[1];}''')
  png=base64.b64decode(blob)
  page.locator('#nb-file').set_input_files([{'name':f'evidence-{i}.png','mimeType':'image/png','buffer':png} for i in range(4)])
  expect(page.locator('.nb-image')).to_have_count(4,timeout=30000);checks['four_images_saved']=True
  page.locator('[data-nb-add=paragraph]').first.click();page.locator('.nb-paragraph textarea').last.fill('여러 화면을 비교한 해석: 요청과 차단 근거를 같은 시각으로 연결했다.')
  page.evaluate('''async()=>{const c=document.createElement('canvas');c.width=400;c.height=140;const x=c.getContext('2d');x.fillStyle='#562f72';x.fillRect(0,0,400,140);x.fillStyle='white';x.font='20px sans-serif';x.fillText('Clipboard evidence',20,70);const b=await new Promise(r=>c.toBlob(r,'image/png'));await navigator.clipboard.write([new ClipboardItem({'image/png':b})]);}''')
  page.locator('.nb-paragraph textarea').last.focus();page.keyboard.press('Control+V');expect(page.locator('.nb-image')).to_have_count(5,timeout=15000);checks['clipboard_adds_fifth_image']=True
  expect(page.locator('.nb-image img')).to_have_count(5);page.locator('.nb-image img').first.scroll_into_view_if_needed();expect(page.locator('.nb-image img').first).to_have_js_property('complete',True);checks['editor_image_pixels_loaded']=page.locator('.nb-image img').first.evaluate('e=>e.naturalWidth>0&&e.getBoundingClientRect().height>20')
  page.locator('.nb-image textarea').last.fill('필터 변경 후 다시 확인한 결과')
  page.locator('.nb-heading [data-nb-move="-1"]').click();checks['blocks_reordered']=page.locator('.nb-block').first.get_attribute('class').endswith('nb-heading')
  page.locator('[data-nb-save=draft]').click();expect(page.locator('#notice')).to_have_text('실습 노트를 저장했습니다.');checks['manual_checkpoint_saved']=True
  # Page navigation must not replace/reorder the journal.
  page.locator('[data-ac-page="1"]').click();expect(page.locator('.nb-image')).to_have_count(5);checks['page_turn_preserves_journal']=True
  page.locator('[data-nb-preview]').click();expect(page.locator('#nb-preview-body img')).to_have_count(5);checks['blog_preview_interleaves_content']=page.locator('#nb-preview-body h3').count()==1 and page.locator('#nb-preview-body pre').count()==1 and page.locator('#nb-preview-body p').count()==2
  checks['student_script_literal']=page.evaluate('window.notebookAttack===undefined') and page.locator('#nb-preview-body').inner_text().find('<script>')>=0
  page.locator('[data-nb-close]').click();page.locator('[data-nb-save=complete]').click();expect(page.locator('#notice')).to_have_text('실습 노트를 완료했습니다.');checks['lesson_completion_saved']=True
  note=page.request.get(origin+'/core/api/academy/lessons/wazuh-threat-hunting/discover').json()['notebook'];rid=note['id'];(out/'record-id.json').write_text(json.dumps({'id':rid}));checks['full_log_round_trip']=next(b['text'] for b in note['notebook'] if b['type']=='code')==long_log
  checks['images_order_persisted']=sum(b['type']=='image' for b in note['notebook'])==5
  page.reload();expect(page.locator('.nb-image')).to_have_count(5);checks['reload_restores_whole_page']=True
  # Capture the top of the clean workspace.
  page.locator('.ac-notebook').evaluate('e=>e.scrollTop=0');page.locator('.ac-reader').evaluate('e=>e.scrollTop=0');page.screenshot(path=str(out/'notebook.png'),full_page=True)
  page.goto(origin+'/core/#academy/record/'+rid);expect(page.locator('.nb-published img')).to_have_count(5);checks['history_has_no_duplicate_images']=page.locator('.ac-record-detail img').count()==5
  options=page.locator('#ac-version option').count();assert options>=2;page.locator('#ac-version').select_option(index=1);expect(page.locator('.nb-published img')).to_have_count(5);checks['manual_revision_readable']=True
  for width in (1440,1024,768):
   page.set_viewport_size({'width':width,'height':1000});page.goto(origin+'/core/#academy/lesson/wazuh-threat-hunting/discover');expect(page.locator('#ac-notebook')).to_be_visible();checks['no_overflow_'+str(width)]=page.evaluate('document.documentElement.scrollWidth<=innerWidth');page.screenshot(path=str(out/f'notebook-{width}.png'),full_page=True)
  page.set_viewport_size({'width':1680,'height':1050});page.goto(origin+'/core/#academy/lesson/wazuh-threat-hunting/case-01');expect(page.locator('.ac-command').first).to_be_attached();checks['command_context_and_results']=page.locator('.ac-command dl').count()>0 and page.locator('.ac-command header').count()>0
  page.locator('.ac-compact-links a').first.click();expect(page.locator('.ac-range-mission')).to_be_visible();checks['livefire_single_submission_stays_disabled']=page.locator('.ac-range-mission textarea').count()==1 and page.locator('.ac-range-mission textarea').is_disabled()
  page.goto(origin+'/core/#datacenter');expect(page.locator('#dc-stage')).to_be_visible();page.locator('[data-dc-mode=building]').click();page.locator('[data-dc-floor="6F"]').click();expect(page.locator('#dc-stage')).to_have_attribute('data-floor','6F')
  page.locator('[data-dc-design=space]').click();learning=page.locator('[data-room-display="MY LEARNING / 내 기록"]')
  checks['floor6_actual_saved_progress']='Discover' in learning.text_content() and '완료 1차시' in learning.text_content()
  page.screenshot(path=str(out/'academy-room.png'),full_page=True)
  page.locator('[data-dc-mode=building]').click();page.locator('[data-dc-floor="7F"]').click();expect(page.locator('#dc-stage')).to_have_attribute('data-floor','7F')
  checks['floor7_display_real_mission_count']='105개 미션' in page.locator('[data-mission-panel=scenarios]').text_content()
  page.screenshot(path=str(out/'livefire-room.png'),full_page=True)
  page.locator('[data-mission-panel=missions] [data-dc-learning-route]').first.focus();page.keyboard.press('Enter');expect(page.locator('.ac-range-mission')).to_be_visible();checks['floor7_screen_keyboard_opens_mission']=True
  page.goto(origin+'/core/#academy/lesson/wazuh-threat-hunting/discover');expect(page.locator('#ac-notebook')).to_be_visible()
  page.locator('.nb-paragraph textarea').first.fill('로그아웃 직전 입력한 마지막 실습 메모')
  page.locator('#logout').click();expect(page.locator('#login')).to_be_visible(timeout=15000)
  page.locator('#login-form input[name=username]').fill('admin');page.locator('#login-form input[name=password]').fill(creds['admin']);page.locator('#login-form button').click()
  expect(page.locator('.nb-paragraph textarea').first).to_have_value('로그아웃 직전 입력한 마지막 실습 메모',timeout=15000);checks['logout_flushes_pending_autosave']=True
  checks['no_script_errors']=not errors
  browser.close()
 (out/'result.json').write_text(json.dumps({'checks':checks,'errors':errors},indent=2));print(json.dumps(checks));assert all(checks.values())
except Exception as e:
    message=traceback.format_exc()
    for secret in creds.values():
        if isinstance(secret,str) and secret:message=message.replace(secret,'[redacted]')
    (out/'error.log').write_text(message)
    raise SystemExit(type(e).__name__+': see redacted error.log in the output directory')
