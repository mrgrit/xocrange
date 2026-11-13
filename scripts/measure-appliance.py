#!/usr/bin/env python3
"""Bounded resource/load sampling on the dedicated acceptance VM."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import time

p=argparse.ArgumentParser()
p.add_argument('--seconds',type=int,default=600)
p.add_argument('--interval',type=int,default=15)
p.add_argument('--load',action='store_true',help='Two harmless HTTP requests/second through the private security path')
p.add_argument('--output',type=Path,required=True)
a=p.parse_args()
if os.geteuid()!=0 or not 15<=a.seconds<=14400 or not 5<=a.interval<=60:p.error('Use sudo, 15–14400 seconds and 5–60 second intervals')
a.output.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
load=None
if a.load:
    code='''import http.client,json,time
end=time.monotonic()+DURATION
counts={"ok":0,"failed":0}
while time.monotonic()<end:
 start=time.monotonic();connection=http.client.HTTPConnection("10.20.30.1",8080,timeout=3)
 try:
  connection.request("GET","/",headers={"Host":"sample.xoc.test","Connection":"close"})
  response=connection.getresponse();response.read(16384);counts["ok" if response.status==200 else "failed"]+=1
 except Exception:counts["failed"]+=1
 finally:connection.close()
 time.sleep(max(0,0.5-(time.monotonic()-start)))
print(json.dumps(counts),flush=True)
'''.replace('DURATION',str(a.seconds))
    load=subprocess.Popen(['docker','exec','xoc-core-security-path-lab-client-1','python','-B','-c',code],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
samples=[];started=time.monotonic();previous=None
try:
    while True:
        mem={k:int(v.split()[0])*1024 for k,v in (line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines())}
        cpu=list(map(int,Path('/proc/stat').read_text().splitlines()[0].split()[1:]));total=sum(cpu[:8]);idle=cpu[3]+cpu[4]
        utilization=None if previous is None else round(100*(1-(idle-previous[1])/max(1,total-previous[0])),2)
        previous=(total,idle)
        disk=shutil.disk_usage('/var/lib/xocrange')
        row={'at':datetime.now(timezone.utc).isoformat(),'elapsed_seconds':round(time.monotonic()-started),
             'memory_total_bytes':mem['MemTotal'],'memory_available_bytes':mem['MemAvailable'],
             'memory_used_bytes':mem['MemTotal']-mem['MemAvailable'],'swap_used_bytes':mem['SwapTotal']-mem['SwapFree'],
             'cpu_percent':utilization,'load_average':os.getloadavg(),'disk_used_bytes':disk.used,'disk_free_bytes':disk.free}
        database=Path('/var/lib/xocrange/siem/events.sqlite3')
        if database.exists():
            with sqlite3.connect('file:'+str(database)+'?mode=ro',uri=True,timeout=10) as db:
                row['siem']={'pending':db.execute('SELECT COUNT(*) FROM events WHERE confirmed IS NULL').fetchone()[0],
                             'native_pending':db.execute('SELECT COUNT(*) FROM native_inputs WHERE confirmed IS NULL').fetchone()[0],
                             'native_oldest':db.execute('SELECT MIN(observed) FROM native_inputs WHERE confirmed IS NULL').fetchone()[0],
                             'index_pending':db.execute('SELECT COUNT(*) FROM events WHERE confirmed IS NOT NULL AND indexed IS NULL').fetchone()[0],
                             'analysis_errors':db.execute('SELECT COUNT(*) FROM processing_errors').fetchone()[0],
                             'health':[list(r) for r in db.execute('SELECT source,status FROM health ORDER BY source')]}
        samples.append(row)
        a.output.write_text(json.dumps({'status':'sampling','samples':samples},indent=2)+'\n');a.output.chmod(0o600)
        if time.monotonic()-started>=a.seconds:break
        time.sleep(min(a.interval,max(0,a.seconds-(time.monotonic()-started))))
    requests=None
    if load:
        out,err=load.communicate(timeout=10)
        if load.returncode:raise RuntimeError('Private load generator failed')
        requests=json.loads(out)
    result={'status':'complete','duration_seconds':round(time.monotonic()-started),'vcpus':os.cpu_count(),
            'memory_peak_bytes':max(r['memory_used_bytes'] for r in samples),
            'cpu_peak_percent':max((r['cpu_percent'] or 0) for r in samples),
            'disk_growth_bytes':samples[-1]['disk_used_bytes']-samples[0]['disk_used_bytes'],
            'requests':requests,'samples':samples}
    a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='samples'},indent=2))
finally:
    if load and load.poll() is None:load.terminate();load.wait(timeout=5)
