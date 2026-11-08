#!/usr/bin/env python3
"""Real isolated Linux agent registration, encrypted transport and reconnect."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time
import uuid
from xocrange.agents import enroll, items
from xocrange.indexer import Client
from xocrange.lab import Docker, checked_plan, host_check
from xocrange.manager_api import ManagerClient


def run(root, plan_name, source, output):
    directory, plan=checked_plan(root,plan_name)
    project=plan['compose']['name'];engine=Docker(directory/'compose.yaml',project)
    if host_check(engine,project)['status']!='ready':raise RuntimeError('Dedicated VM checks failed')
    name='xoc-agent-'+uuid.uuid4().hex[:12]
    output.mkdir(mode=0o700,parents=True,exist_ok=True)
    output.chmod(0o700)
    key=output/'client.keys'
    client=ManagerClient(engine,project);token=client.authenticate();checks={}
    identity=enroll(client,name,key);ident=identity['id']
    image='xoc-k06-agent:4.14.10'
    index=Client(engine,project,user='admin')
    def wait(predicate, seconds=120):
        deadline=time.monotonic()+seconds
        while time.monotonic()<deadline:
            if predicate():return True
            time.sleep(2)
        return False
    def active():
        rows=items(client,token,'/agents?agents_list='+ident)
        ready=subprocess.run(['docker','exec',name,'test','-f','/run/xoc-agent-ready'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0
        return ready and bool(rows) and rows[0].get('status')=='active' and rows[0].get('version')=='Wazuh v4.14.10'
    def hits(marker):
        code,data=index.request('POST','/wazuh-alerts-4.x-*/_search',{'size':10,'query':{'bool':{'filter':[{'term':{'agent.id':ident}},{'match_phrase':{'full_log':marker}}]}}})
        return data.get('hits',{}).get('hits',[]) if code==200 else []
    def probe(marker):
        line=time.strftime('%b %d %H:%M:%S')+' endpoint sshd[4422]: Invalid user '+marker+' from 192.0.2.44 port 40000\n'
        subprocess.run(['docker','exec','-i',name,'python3','-c',"import sys;open('/var/log/xoc-agent-probe.log','a').write(sys.stdin.read())"],input=line,text=True,check=True)
    started=False; disconnected=False
    try:
        subprocess.run(['docker','build','--tag',image,str(source/'tests/integration/agent')],check=True,stdout=subprocess.DEVNULL)
        subprocess.run(['docker','run','-d','--name',name,'--hostname',name,'--label','com.docker.compose.project='+project,
                        '--label','com.xocrange.validation=agent-transport','--network',project+'_int',
                        '--cap-drop','ALL',*sum((['--cap-add',c] for c in ['CHOWN','DAC_OVERRIDE','FOWNER','KILL','SETUID','SETGID','SYS_CHROOT']),[]),
                        '--security-opt','no-new-privileges:true','--mount','type=bind,src='+str(key)+',dst=/run/identity/client.keys,readonly',
                        '--tmpfs','/tmp:size=32m',image],check=True,stdout=subprocess.DEVNULL)
        started=True
        checks['agent_registered_and_active']=wait(active)
        checks['agent_key_private']=key.stat().st_mode&0o777==0o600
        checks['reenroll_preserves_identity']=enroll(client,name,key)['id']==ident
        marker='xocagent'+uuid.uuid4().hex;probe(marker)
        checks['agent_event_indexes_with_true_identity']=wait(lambda:bool(hits(marker)))
        found=hits(marker)
        checks['stock_sshd_detection']=len(found)==1 and found[0]['_source']['rule']['id']=='5710'
        subprocess.run(['docker','network','disconnect',project+'_int',name],check=True)
        disconnected=True
        offline='xocoffline'+uuid.uuid4().hex;probe(offline)
        time.sleep(12)
        checks['disconnected_event_not_falsely_delivered']=not hits(offline)
        subprocess.run(['docker','network','connect',project+'_int',name],check=True);disconnected=False
        checks['reconnect_delivers_queued_event']=wait(lambda:bool(hits(offline)))
        checks['reconnect_unique_event']=len(hits(offline))==1
        subprocess.run(['docker','restart',name],check=True,stdout=subprocess.DEVNULL)
        checks['agent_restart_preserves_registration']=wait(active)
        again='xocrestarted'+uuid.uuid4().hex;probe(again)
        checks['post_restart_event']=wait(lambda:bool(hits(again)))
        checks['restart_does_not_duplicate_prior_events']=len(hits(marker))==len(hits(offline))==1
        checks['no_agent_host_ports']=not json.loads(subprocess.check_output(['docker','inspect',name],text=True))[0]['HostConfig']['PortBindings']
    finally:
        if started:subprocess.run(['docker','rm','-f',name],check=True,stdout=subprocess.DEVNULL)
        code, reply=client.request('DELETE','/agents?agents_list='+ident+'&status=all&older_than=0s',token=token)
        checks['test_agent_removed']=code==200 and not reply.get('data',{}).get('total_failed_items',1)
        key.unlink(missing_ok=True)
    result={'status':'passed' if all(checks.values()) else 'failed','checks':checks,'scope':'Real Linux agent in an isolated container on the dedicated xoc VM; no separate physical/Windows host claim.'}
    (output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,required=True);parser.add_argument('--plan',required=True);parser.add_argument('--source',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--isolated-vm',action='store_true',required=True)
    args=parser.parse_args();result=run(args.root,args.plan,args.source,args.output);print(json.dumps(result,indent=2));raise SystemExit(0 if result['status']=='passed' else 2)
