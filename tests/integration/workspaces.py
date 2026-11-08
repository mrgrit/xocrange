#!/usr/bin/env python3
"""K09 HTTPS checks; --exercise-observer briefly stops only the fixture target."""
import argparse,importlib.util,json,secrets,subprocess,sys,time,uuid
from datetime import datetime,timedelta,timezone
from pathlib import Path

p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('plan');p.add_argument('--exercise-observer',action='store_true');p.add_argument('--output',type=Path,required=True);a=p.parse_args()
from xocrange.lab import Docker,checked_plan
from xocrange.platform_setup import STATE
from xocrange.ui_setup import private_json,owned_volume
spec=importlib.util.spec_from_file_location('gateway',a.root/'scripts/verify-platform.py');gateway=importlib.util.module_from_spec(spec);spec.loader.exec_module(gateway)
directory,plan=checked_plan(a.root,a.plan);engine=Docker(directory/'compose.yaml',plan['compose']['name'])
c=private_json(STATE/'credentials.json');s=gateway.Session(c['public_host']);checks={}
for path in ('registry','noc','library'):
    checks['anonymous_'+path+'_denied']=s.request('/core/api/'+path)[0]==401
checks['login_through_security_path']=s.login('admin',c.get('admin_password',c['bootstrap_password']))[0]==200
code,data,headers,raw=s.request('/core/api/registry')
checks['authenticated_registry']=code==200
checks['selected_components_only']={v['id'] for v in data['components']}==set(plan['lock']['selected'])
checks['selected_services_only']={v['service'] for v in data['assets']}==set(plan['compose']['services'])
checks['fresh_observations']=data['observation']['fresh']
checks['container_state_scope']=data['observation']['scope']=='container_state'
checks['no_secrets_in_registry']=not any(str(c[key]).encode() in raw for key in ('secret_key','bootstrap_password','admin_password') if key in c)
checks['no_store']='no-store' in headers.get('Cache-Control','')
checks['no_web_docker_socket']=all('docker.sock' not in v for v in plan['compose']['services']['platform'].get('volumes',[]))
checks['read_only_observation_mount']='platform-observation:/run/xoc-observation:ro' in plan['compose']['services']['platform']['volumes']
selected=set(plan['lock']['selected'])
code,noc,_,_=s.request('/core/api/noc')
checks['noc_selection']=code==(200 if 'noc' in selected else 404)
if code==200:checks['only_second_floor']=noc['floor']=='2F' and {a['floor'] for a in noc['assets']}=={'2F'}
code,library,_,_=s.request('/core/api/library');checks['reader_selection']=code==(200 if 'academy-reader' in selected else 404)
if code==200:
    checks['all_selected_guides_readable']=bool(library['articles']) and all(s.request('/core/api/library/'+i['id'])[0]==200 for i in library['articles'])
    checks['unknown_guide_rejected']=s.request('/core/api/library/not-a-guide')[0]==404
for path in ('registry','noc','library'):
    checks[path+'_no_write_action']=s.request('/core/api/'+path,{})[0]==405
code,session,_,_=s.request('/core/api/session')
checks['navigation_matches_selection']={p['component_id'] for p in session['navigation']}=={m['component_id'] for m in plan['registry']['panels']}
name='k09_'+uuid.uuid4().hex[:12];password='K09-Test!'+secrets.token_urlsafe(24);viewer=gateway.Session(c['public_host'])
try:
    checks['create_temporary_viewer']=s.request('/core/api/users',dict(username=name,role='viewer',active=True,password=password))[0]==201
    checks['viewer_login']=viewer.login(name,password)[0]==200
    checks['first_password_gate']=viewer.request('/core/api/registry')[0]==403
    checks['viewer_password_change']=viewer.request('/core/api/password',dict(current_password=password,password='Changed!'+secrets.token_urlsafe(24)))[0]==200
    checks['viewer_registry']=viewer.request('/core/api/registry')[0]==200
    checks['viewer_cannot_write_policy']=viewer.request('/core/api/devices/fw',dict(write_enabled=True,version=1))[0]==403
finally:
    checks['temporary_viewer_disabled']=s.request('/core/api/users',dict(username=name,role='viewer',active=False))[0]==200
checks['disabled_session_revoked']=viewer.request('/core/api/registry')[0]==401
cleanup="import os,sys;os.environ['DJANGO_SETTINGS_MODULE']='settings';import django;django.setup();from django.contrib.auth.models import User;User.objects.filter(username=sys.argv[1],is_active=False).delete();print(not User.objects.filter(username=sys.argv[1]).exists())"
checks['temporary_viewer_removed']=engine.run(['exec','-T','platform','python','-B','-c',cleanup,name],compose=True).strip()=='True'
if a.exercise_observer:
    if 'lab-target' not in plan['compose']['services']:raise SystemExit('Observer exercise requires the disposable fixture target')
    def observe():subprocess.run([sys.executable,str(a.root/'scripts/observe-registry.py'),str(a.root),a.plan],check=True,capture_output=True)
    def state(service):
        value=s.request('/core/api/registry')[1]
        return next(x['health']['state'] for x in value['assets'] if x['service']==service)
    baseline_ids={x['service']:x['asset_id'] for x in data['assets']}
    try:
        engine.run(['stop','lab-target'],compose=True)
        observe();checks['stopped_target_observed']=state('lab-target')=='exited'
        checks['management_works_with_target_down']=s.request('/core/api/devices')[0]==200
    finally:
        engine.run(['start','lab-target'],compose=True)
        observe()
    checks['target_recovery_observed']=state('lab-target')=='running'
    checks['asset_ids_survive_restart']={x['service']:x['asset_id'] for x in s.request('/core/api/registry')[1]['assets']}==baseline_ids
    subprocess.run(['systemctl','stop','xocrange-observer.timer','xocrange-observer.service'],check=True)
    location=owned_volume(engine,plan['compose']['name'],'platform-observation')/'health.json'
    try:
        observation=json.loads(location.read_text());observation['observed_at']=(datetime.now(timezone.utc)-timedelta(seconds=90)).isoformat();location.write_text(json.dumps(observation))
        stale=s.request('/core/api/registry')[1]
        checks['stale_observation_not_green']=not stale['observation']['fresh'] and all(x['health']['state']=='unknown' for x in stale['assets'])
    finally:
        subprocess.run(['systemctl','start','xocrange-observer.service','xocrange-observer.timer'],check=True)
    checks['observer_recovery']=s.request('/core/api/registry')[1]['observation']['fresh']
checks['logout']=s.request('/core/api/logout',{})[0]==200
checks['logout_revokes_inventory']=s.request('/core/api/registry')[0]==401
report={'status':'passed' if all(checks.values()) else 'failed','checks':checks,'scope':'Actual HTTPS/WAF; selected C4/C5, reader, roles, optional fixture service/observer faults.'}
a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2));raise SystemExit(report['status']!='passed')
