#!/usr/bin/env python3
"""Read-only catalog and building/floor navigation acceptance."""
import argparse,json,traceback
from pathlib import Path
from playwright.sync_api import sync_playwright,expect
p=argparse.ArgumentParser();p.add_argument('--url',required=True);p.add_argument('--credentials',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--proxy');p.add_argument('--ignore-https-errors',action='store_true');a=p.parse_args()
assert not a.credentials.is_symlink() and not a.credentials.stat().st_mode&0o077
secret=json.loads(a.credentials.read_text());password=secret.get('admin',secret.get('password'));out=a.output;out.mkdir(parents=True,exist_ok=True);base=a.url.rstrip('/');checks={};errors=[]
try:
 with sync_playwright() as pw:
  b=pw.chromium.launch();opts={'ignore_https_errors':a.ignore_https_errors,'viewport':{'width':1680,'height':1050}}
  if a.proxy:opts['proxy']={'server':a.proxy}
  page=b.new_page(**opts);page.on('pageerror',lambda e:errors.append(str(e)))
  page.goto(base+'/core/#datacenter');page.locator('#login-form [name=username]').fill('admin');page.locator('#login-form [name=password]').fill(password);page.locator('#login-form button').click();expect(page.locator('[data-dc-floor="6F"]')).to_be_visible(timeout=30000)
  def overview(prefix):
   checks[prefix+'_no_status_panels']=page.locator('#dc-learning,.dc-header-metric,.dc-status').count()==0
   checks[prefix+'_no_learning_text_on_building']=page.locator('.dc-room-screen text').count()==0
   checks[prefix+'_full_width_canvas']=page.locator('#dc-scene').bounding_box()['width']/page.locator('#dc-stage').bounding_box()['width']>.95
   checks[prefix+'_all_eleven_floors']=page.locator('[data-dc-floor]').count()==11
  overview('initial');page.screenshot(path=str(out/'building.png'),full_page=True)
  page.locator('[data-dc-floor="6F"]').click();expect(page.locator('.al-card')).to_have_count(24)
  checks['floor6_stays_in_catalog']=page.url.endswith('#datacenter') and page.locator('#dc-stage').get_attribute('data-floor')=='6F' and page.locator('.ac-reader,.ac-course-banner').count()==0
  checks['one_available_among_24']=page.locator('a.al-card.is-available').count()==1 and page.locator('article.al-card.is-unavailable').count()==23
  checks['bundle_has_no_expanded_details']=all(x not in page.locator('.al-card.is-available').inner_text() for x in ('339','36','96','교재 페이지','미션'))
  checks['uninstalled_cards_inert']=page.locator('.al-card.is-unavailable').evaluate_all("xs=>xs.every(e=>!e.hasAttribute('href')&&!e.hasAttribute('tabindex')&&e.getAttribute('aria-disabled')==='true'&&getComputedStyle(e).filter.includes('grayscale(1)'))")
  page.locator('.al-card.is-unavailable').first.click();checks['uninstalled_click_keeps_catalog']=page.url.endswith('#datacenter')
  checks['uninstalled_api_denied']=page.request.get(base+'/core/api/academy/courses/secuops').status==404
  expect(page.locator('.al-card.is-available img')).to_have_js_property('complete',True);checks['thumbnail_loaded']=page.locator('.al-card.is-available img').evaluate('e=>e.naturalWidth>0')
  page.screenshot(path=str(out/'catalog.png'),full_page=True)
  page.locator('[data-al-search]').fill('AI');checks['title_search']=page.locator('.al-card:visible').count()>5 and page.locator('.al-card:visible').evaluate_all("xs=>xs.every(e=>e.dataset.alTitle.includes('ai'))")
  page.locator('[data-al-available]').click();checks['combined_filter_empty_state']=page.locator('.al-card:visible').count()==0 and page.locator('.al-empty').is_visible()
  page.locator('[data-al-search]').fill('');checks['available_filter_one']=page.locator('.al-card:visible').count()==1
  page.locator('[data-al-available]').click();page.locator('[data-al-category]').select_option(label='융합 보안');checks['category_filter']=page.locator('.al-card:visible').count()==2
  page.locator('[data-al-category]').select_option('');page.locator('a.al-card').focus();page.keyboard.press('Enter');expect(page.locator('.ac-lesson-card')).to_have_count(36);checks['bundle_opens_course_not_lesson']=page.url.endswith('#academy/course/wazuh-threat-hunting') and page.locator('.ac-reader').count()==0
  page.goto(base+'/core/#datacenter');expect(page.locator('.al-card')).to_have_count(24)
  page.locator('[data-dc-design=space]').click();expect(page.locator('.dc-room-screen').first).to_be_visible();checks['floor6_display_real_titles']='시스템 침투와 SIEM 분석' in page.locator('.dc-room-screen').first.text_content() and '24개 콘텐츠' in page.locator('.dc-room-screen').first.text_content()
  checks['floor6_personal_status_inside']='내 기록' in page.locator('[data-room-display="MY LEARNING / 내 기록"]').text_content()
  page.screenshot(path=str(out/'academy-space.png'),full_page=True)
  page.locator('[data-dc-mode=building]').click();expect(page.locator('[data-dc-floor="7F"]')).to_be_visible();overview('return_from6')
  page.locator('[data-dc-floor="7F"]').click();expect(page.locator('#dc-stage')).to_have_attribute('data-floor','7F');checks['floor7_actual_missions']='105개 미션' in page.locator('[data-mission-panel=scenarios]').text_content()
  page.screenshot(path=str(out/'livefire-space.png'),full_page=True)
  page.locator('[data-mission-panel=missions] [data-dc-learning-route]').first.focus();page.keyboard.press('Enter');expect(page.locator('.ac-range-mission')).to_be_visible();checks['floor7_screen_opens_mission']=True
  page.goto(base+'/core/#datacenter');expect(page.locator('#dc-stage')).to_be_visible();page.locator('[data-dc-mode=building]').click();expect(page.locator('[data-dc-floor="6F"]')).to_be_visible();overview('return_from7')
  page.goto(base+'/core/#academy');expect(page.locator('.al-card')).to_have_count(24);checks['sidebar_same_catalog']=page.locator('a.al-card').count()==1
  page.locator('[data-nav=datacenter]').click();expect(page.locator('#dc-stage')).to_have_attribute('data-mode','building');overview('sidebar_home')
  page.goto(base+'/core/#datacenter');page.locator('[data-dc-mode=building]').click();page.locator('[data-dc-floor="6F"]').click();expect(page.locator('.al-card')).to_have_count(24)
  for width,height in [(1440,1000),(1024,900),(768,900),(430,900),(320,740)]:
   page.set_viewport_size({'width':width,'height':height});page.wait_for_timeout(100);checks['catalog_'+str(width)+'_no_overflow']=page.evaluate('document.documentElement.scrollWidth<=innerWidth');page.screenshot(path=str(out/f'catalog-{width}.png'),full_page=True)
  page.set_viewport_size({'width':1680,'height':1050});page.locator('#logout').click();expect(page.locator('#login')).to_be_visible();page.locator('#login-form [name=username]').fill('admin');page.locator('#login-form [name=password]').fill(password);page.locator('#login-form button').click();expect(page.locator('#dc-stage')).to_have_attribute('data-mode','building');overview('login_home')
  checks['no_script_errors']=not errors;b.close()
 result={'checks':checks,'errors':errors};(out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'checks':len(checks),'failed':[k for k,v in checks.items() if not v]}));assert all(checks.values())
except Exception:
 error=traceback.format_exc().replace(password,'[redacted]');(out/'error.log').write_text(error);raise SystemExit('Catalog browser failed; see redacted error.log')
