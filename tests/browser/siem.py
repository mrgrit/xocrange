#!/usr/bin/env python3
"""Optional browser acceptance against the real deployed HTTPS WAF path.

Install the browser-test extra and Chromium in the test environment. Credentials
are read from a private JSON file; the test report never contains their values.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import ssl
import subprocess
import urllib.request

from playwright.sync_api import sync_playwright


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--url',required=True)
    parser.add_argument('--credentials',type=Path,required=True)
    parser.add_argument('--certificate',type=Path,required=True)
    parser.add_argument('--ca',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.credentials.is_symlink() or args.credentials.stat().st_mode & 0o077:
        raise SystemExit('Credentials must be a private regular file')
    secret=json.loads(args.credentials.read_text())
    base=args.url.rstrip('/')
    # Verify CA and hostname normally before pinning this leaf for Chromium's
    # isolated test profile. No production TLS verification setting is disabled.
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(args.ca))))
    with opener.open(base+'/siem/',timeout=30) as response:
        assert response.status==200
    public=subprocess.check_output(['openssl','x509','-in',str(args.certificate),'-pubkey','-noout'])
    der=subprocess.run(['openssl','pkey','-pubin','-outform','DER'],input=public,capture_output=True,check=True).stdout
    pin=base64.b64encode(hashlib.sha256(der).digest()).decode()
    checks={};errors=[];searches=[]
    with sync_playwright() as playwright:
        browser=playwright.chromium.launch(headless=True,args=['--ignore-certificate-errors-spki-list='+pin])
        context=browser.new_context(viewport={'width':1440,'height':1000})
        page=context.new_page()
        page.on('response',lambda r: errors.append({'status':r.status,'path':r.url.removeprefix(base).split('?')[0]}) if r.status>=400 else None)
        page.on('response',lambda r: searches.append(r.status) if '/internal/search/' in r.url else None)
        page.goto(base+'/siem/',wait_until='networkidle',timeout=60000)
        checks['login_form']=page.locator('input[type=password]').is_visible()
        page.locator('input[type=text]').fill(secret['username'])
        page.locator('input[type=password]').fill(secret['password'])
        page.locator('button[type=submit]').click()
        page.wait_for_url(re.compile(r'.*/siem/app/dashboards.*'),timeout=60000)
        page.get_by_text('xOC Range · Security overview',exact=True).first.wait_for(timeout=60000)
        page.locator('[data-test-subj=queryInput]').wait_for()
        page.wait_for_timeout(4000)
        checks['four_dashboard_panels']=page.locator('[data-test-subj="dashboardPanel"]').count()==4
        checks['secure_httponly_cookie']=any(c['secure'] and c['httpOnly'] for c in context.cookies())
        checks['custom_logo_loaded']=page.locator('img[src="/assets/xoc-range-logo.png"]').evaluate_all('(xs)=>xs.some(x=>x.complete && x.naturalWidth>0)')
        # Unauthenticated plugin probes on the login screen can legitimately be
        # 401. From this point, authenticated UI operations must have no 4xx/5xx.
        errors.clear()
        page.reload(wait_until='domcontentloaded')
        page.locator('[data-test-subj=queryInput]').wait_for()
        checks['session_survives_reload']='/app/login' not in page.url
        page.goto(base+'/siem/app/discover#/view/xoc-events-search',wait_until='domcontentloaded')
        editor=page.locator('[data-test-subj=queryInput]');editor.wait_for(timeout=60000)
        page.wait_for_timeout(2000)
        for name,query in [('source_filter','producer : "suricata"'),('file_path_search','process.executable : "/root/.profile"'),('all_events','')]:
            before=len(searches)
            editor.fill(query);editor.press('Enter')
            page.wait_for_timeout(2500)
            checks[name]=len(searches)>before and all(code==200 for code in searches[before:])
        page.reload(wait_until='domcontentloaded')
        page.locator('[data-test-subj=queryInput]').wait_for()
        checks['discover_deep_link_reload']='/discover/' in page.url and '/app/login' not in page.url
        page.wait_for_timeout(12000)
        checks['no_authenticated_http_errors']=not errors
        checks['no_search_error_notice']='Search Error' not in page.locator('body').inner_text()
        args.output.parent.mkdir(parents=True,exist_ok=True)
        page.screenshot(path=str(args.output.with_suffix('.png')))
        browser.close()
    report={'status':'passed' if all(checks.values()) else 'failed','checks':checks,'http_errors':errors}
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    return 0 if report['status']=='passed' else 2


if __name__=='__main__':raise SystemExit(main())
