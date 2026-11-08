#!/usr/bin/env python3
"""Non-mutating gateway acceptance; never logs in or changes bootstrap password."""
import importlib.util
import json
from pathlib import Path
import sys
import time
from xocrange.platform_setup import STATE
from xocrange.ui_setup import private_json

root=Path(sys.argv[1])
spec=importlib.util.spec_from_file_location('gateway_probe',root/'scripts/verify-platform.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
session=module.Session(private_json(STATE/'credentials.json')['public_host'])
deadline=time.monotonic()+60
while True:
    try:
        code,data,_,_=session.request('/core/api/session')
        if code==200 and data.get('csrf_token'):break
    except (OSError,ValueError):pass
    if time.monotonic()>=deadline:raise SystemExit('Common management gateway did not become ready')
    time.sleep(2)
checks={'anonymous_session':not data.get('authenticated'),
        'login_page':session.request('/core/')[0]==200,
        'javascript':session.request('/core/assets/app.js')[0]==200,
        'anonymous_devices_denied':session.request('/core/api/devices')[0]==401,
        'anonymous_users_denied':session.request('/core/api/users')[0]==401,
        'anonymous_audit_denied':session.request('/core/api/audit')[0]==401}
report={'status':'passed' if all(checks.values()) else 'failed','checks':checks}
Path('/var/lib/xocrange/management-acceptance.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2));raise SystemExit(0 if report['status']=='passed' else 2)
