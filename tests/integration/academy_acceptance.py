#!/usr/bin/env python3
"""Exercise the installed reader and literal evidence through real HTTPS/WAF."""
import argparse
import base64
import importlib.util
import json
import secrets
import struct
import zlib
from pathlib import Path
import subprocess
import sys
import uuid
from admin_credential import admin_password

p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
state=Path('/var/lib/xocrange');installed=json.loads((state/'last-install.json').read_text());root=Path(installed['release'])
spec=importlib.util.spec_from_file_location('gateway',root/'scripts/verify-platform.py');gateway=importlib.util.module_from_spec(spec);spec.loader.exec_module(gateway)
cred=json.loads((state/'platform/credentials.json').read_text());Session=gateway.Session;admin=Session(cred['public_host']);other=Session(cred['public_host']);anon=Session(cred['public_host']);checks={};records=[]
username='academy_'+uuid.uuid4().hex[:12];password='Academy-Test!'+secrets.token_urlsafe(24)
created=False
base='/core/api/academy';cid='wazuh-threat-hunting'
def check(name,condition):
 checks[name]=bool(condition)
 if not condition:raise AssertionError(name)
def save():
 a.output.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 a.output.write_text(json.dumps({'status':'passed' if checks and all(checks.values()) else 'failed','checks':checks,'release':root.name},indent=2));a.output.chmod(0o600)
try:
 check('anonymous_read_denied',anon.request(base)[0]==401)
 anon.request('/core/api/session')
 check('anonymous_write_denied',anon.request(base+'/records',{})[0]==401)
 check('admin_login',admin.login('admin',admin_password(cred))[0]==200)
 status,catalog,_,_=admin.request(base);check('catalog_339_pages',status==200 and catalog['courses'][0]['public_pages']==339)
 status,lesson,_,_=admin.request(base+'/lessons/'+cid+'/case-30');check('last_lesson_stops_at_339',status==200 and max(s['page'] for s in lesson['slides'])==339)
 check('unpublished_lesson_denied',admin.request(base+'/lessons/'+cid+'/case-31')[0]==404)
 check('csrf_enforced',admin.request(base+'/records',{},headers={'X-CSRFToken':''})[0]==403)
 check('other_origin_denied',admin.request(base+'/records',{},headers={'Origin':'https://other.example'})[0]==403)
 value={'course':cid,'lesson':'case-01','mission':'case-01-execute','input':"1' UNION SELECT user,password FROM users-- ; cat /etc/passwd",'output':'HTTP 403\n<script>alert(1)</script>\n${jndi:ldap://example.invalid/a}', 'interpretation':'차단 결과와 원본 로그를 함께 비교한 기록', 'status':'draft','revision':0}
 status,r,_,raw=admin.request(base+'/records',value)
 check('literal_sql_xss_shell_evidence_saved_through_waf',status==201)
 rid=r['id'];records.append(rid)
 check('record_text_preserved',all(r[k]==value[k] for k in ['input','output','interpretation']))
 check('waf_still_inspects_mission_id',admin.request(base+'/records',value|{'mission':'<script>alert(1)</script>'})[0]==403)
 check('waf_still_inspects_other_route',admin.request('/core/api/devices/fw',{'input':'<script>alert(1)</script>'})[0]==403)
 check('waf_marker_still_blocked',admin.request(base+'/records',value,headers={'X-Xoc-Probe':'waf-block'})[0]==403)
 image='data:image/png;base64,'+base64.b64encode(bytes.fromhex('89504e470d0a1a0a0000000d4948445200000001000000010802000000907753de0000000c49444154789c63f8cfc000000301010018dd8db00000000049454e44ae426082')).decode()
 status,r,_,_=admin.request(base+'/records/'+rid+'/images',{'image':image,'caption':'출력 캡처','revision':1})
 check('image_saved_through_waf',status==201)
 url=r['images'][0]['url'];status,_,headers,binary=admin.request(url)
 check('image_loaded_from_db',status==200 and headers.get('Content-Type')=='image/webp' and binary[:4]==b'RIFF')
 check('image_caption_still_inspected',admin.request(base+'/records/'+rid+'/images',{'image':image,'caption':'<script>alert(1)</script>','revision':2})[0]==403)
 check('oversized_image_rejected',admin.request(base+'/records/'+rid+'/images',{'image':'A'*760000,'caption':'','revision':2})[0]==413)
 # A valid near-limit screenshot exercises proxy buffering and WAF exceptions.
 def chunk(kind,value):return struct.pack('>I',len(value))+kind+value+struct.pack('>I',zlib.crc32(kind+value))
 noise=b''.join(b'\x00'+secrets.token_bytes(380*3) for _ in range(380))
 large=b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',380,380,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(noise))+chunk(b'IEND',b'')
 status,r,_,_=admin.request(base+'/records/'+rid+'/images',{'image':'data:image/png;base64,'+base64.b64encode(large).decode(),'caption':'실제 크기 캡처','revision':2})
 check('large_valid_screenshot_saved',len(large)>400000 and status==201)
 check('record_complete_with_image' ,admin.request(base+'/records/'+rid,value|{'output':'','status':'complete','revision':3})[0]==200)
 check('stale_revision_rejected',admin.request(base+'/records/'+rid,value|{'revision':1})[0]==409)
 check('old_revision_preserved',admin.request(base+'/records/'+rid+'/revisions/1')[1]['snapshot']['output']==value['output'])
 check('own_history_visible',any(row['id']==rid for row in admin.request(base+'/history')[1]['records']))
 check('create_second_learner',admin.request('/core/api/users',{'username':username,'role':'viewer','active':True,'password':password})[0]==201);created=True
 check('second_learner_login',other.login(username,password)[0]==200)
 newpass='Academy-Changed!'+secrets.token_urlsafe(24)
 check('second_learner_password_change',other.request('/core/api/password',{'current_password':password,'password':newpass})[0]==200)
 check('other_record_denied',other.request(base+'/records/'+rid)[0]==404)
 check('other_image_denied',other.request(url)[0]==404)
 check('other_revision_denied',other.request(base+'/records/'+rid+'/revisions/1')[0]==404)
 check('other_write_denied',other.request(base+'/records/'+rid,value|{'revision':4})[0]==404)
 check('other_history_empty',other.request(base+'/history')[1]['count']==0)
 check('viewer_can_save_own_record',other.request(base+'/records',value)[0]==201)
 check('core_ai_disabled',r['evaluation']['ai_available'] is False and r['evaluation']['minimum_tier']=='live-fire')
 checks['exercise_completed']=True
finally:
 if created:admin.request('/core/api/users',{'username':username,'role':'viewer','active':False})
 admin.request('/core/api/logout',{});other.request('/core/api/logout',{})
 checks.setdefault('exercise_completed',False);save()
print(json.dumps({'status':'passed' if all(checks.values()) else 'failed','checks':len(checks)}))
