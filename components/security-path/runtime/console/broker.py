"""Device-local Unix RPC. No TCP listener, Docker socket, arbitrary path or shell command."""
import copy
from datetime import datetime, timezone
import difflib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import socketserver
import struct
import subprocess
import sys
import time
from engine import candidate, compile_policy, empty, run, tail


class Conflict(Exception): pass


def atomic(path, data):
    temporary=path.with_suffix(path.suffix+'.tmp')
    with temporary.open('w') as stream:
        stream.write(data);stream.flush();os.fsync(stream.fileno())
    temporary.replace(path)
    fd=os.open(path.parent,os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)


class Device:
    def __init__(self,device,base=Path('/var/lib/xoc-console')):
        self.device=device;self.base=base;self.base.mkdir(parents=True,exist_ok=True)
        self.path=base/'state.json';self.current=base/'current.conf';self.check=base/'candidate.conf'
        if not self.path.exists(): atomic(self.path,json.dumps(empty()))

    def state(self): return json.loads(self.path.read_text())

    def initialize(self):
        state=self.state();text=compile_policy(self.device,state)
        atomic(self.current,text);atomic(self.check,text)
        if self.device=='fw': run(['nft','-f',str(self.current)])

    def validate(self,text):
        atomic(self.check,text)
        if self.device=='fw': return run(['nft','-c','-f',str(self.check)])
        if self.device=='ips':
            import yaml
            config=yaml.safe_load(Path('/run/xoc-suricata.yaml').read_text())
            config['rule-files']=['/etc/xoc/probe.rules',str(self.check)]
            config['unix-command']={'enabled':False};config['pid-file']=str(self.base/'test.pid')
            config['default-log-dir']=str(self.base);config['outputs']=[]
            test=self.base/'check.yaml';atomic(test,yaml.safe_dump(config,version=(1,1),explicit_start=True))
            return run(['suricata','-T','--init-errors-fatal','-c',str(test)])
        return run(['apache2ctl','-t','-D','XOC_CONSOLE_VALIDATE'])

    def activate(self,text):
        atomic(self.current,text)
        if self.device=='fw': run(['nft','-f',str(self.current)])
        elif self.device=='ips':
            response=run(['suricatasc','-c','reload-rules','/run/suricata-command.socket'])
            if '"OK"' not in response: raise ValueError('Suricata reload did not succeed')
        else: run(['apache2ctl','-k','graceful'])

    def journal(self,entry):
        with (self.base/'operations.jsonl').open('a') as stream:
            stream.write(json.dumps(entry,ensure_ascii=False)+'\n');stream.flush();os.fsync(stream.fileno())

    def status(self):
        state=self.state();result={k:v for k,v in state.items() if k!='history'}
        result.update(device=self.device,history=[{k:v for k,v in h.items() if k!='previous'} for h in reversed(state['history'])],
                      generated=compile_policy(self.device,state),observed_at=datetime.now(timezone.utc).isoformat())
        if self.device=='fw':
            result.update(engine=run(['nft','--version']).strip(),raw=run(['nft','-a','list','ruleset']),interfaces=json.loads(run(['ip','-j','addr'])))
            data=json.loads(run(['nft','-j','list','table','inet','xoc_policy']))
            result['system_rules']=[i['rule'] for i in json.loads(run(['nft','-j','list','table','inet','xoc_fw']))['nftables'] if 'rule' in i and i['rule'].get('chain')=='forward']
            result['counters']={}
            for item in data['nftables']:
                r=item.get('rule',{});identifier=r.get('comment','').removeprefix('xoc:')
                if identifier:
                    result['counters'][identifier]=next((x['counter'] for x in r.get('expr',[]) if isinstance(x.get('counter'),dict)),{})
            result['events']=tail('/var/log/nftables/events.log')
        elif self.device=='ips':
            result.update(engine=run(['suricata','-V']).strip(),raw=Path('/etc/xoc/probe.rules').read_text()+'\n'+result['generated'],events=tail('/var/log/suricata/eve.json'))
        else:
            result.update(engine=run(['apache2','-v']).splitlines()[0],raw=Path('/etc/modsecurity/xoc.conf').read_text()+'\n'+result['generated'],events=tail('/var/log/apache2/error.log'),crs_files=sorted(p.name for p in Path('/usr/share/modsecurity-crs/rules').glob('*.conf')))
        return result

    def request(self,body):
        if not isinstance(body,dict) or body.keys()-{'action','version','payload','token','actor','request_id'}: raise ValueError('Invalid request')
        action=body.get('action');state=self.state()
        if action=='status': return self.status()
        if action not in ('preview','apply'): raise ValueError('Unknown action')
        if type(body.get('version')) is not int or state['version']!=body['version']: raise Conflict('Policy changed; refresh and review again')
        actor=body.get('actor','');request_id=body.get('request_id','')
        if not isinstance(actor,str) or not actor or len(actor)>32: raise ValueError('Actor required')
        if action=='preview':
            next_state=candidate(self.device,state,body.get('payload'));text=compile_policy(self.device,next_state)
            self.validate(text)
            token=secrets.token_hex(24)
            ticket={'token':token,'expires':time.time()+120,'actor':actor,'version':state['version'],'candidate':next_state,'operation':body['payload']['operation']}
            # One ticket per device: a newer preview supersedes an older preview, never the running policy.
            atomic(self.base/'ticket.json',json.dumps(ticket))
            diff=''.join(difflib.unified_diff(compile_policy(self.device,state).splitlines(True),text.splitlines(True),fromfile='running',tofile='candidate'))
            return {'token':token,'version':state['version'],'expires_in':120,'valid':True,'diff':diff,'generated':text}
        ticket=json.loads((self.base/'ticket.json').read_text()) if (self.base/'ticket.json').exists() else {}
        if not secrets.compare_digest(str(body.get('token','')),ticket.get('token','missing')) or ticket.get('expires',0)<time.time() or ticket.get('actor')!=actor or ticket.get('version')!=state['version']:
            raise Conflict('Review expired or replaced; validate again')
        next_state=ticket['candidate'];text=compile_policy(self.device,next_state);previous=compile_policy(self.device,state)
        self.validate(text)
        at=datetime.now(timezone.utc).isoformat();operation={'at':at,'actor':actor,'request_id':request_id,'operation':ticket['operation'],'version':next_state['version']}
        self.journal(dict(operation,outcome='started'))
        try:
            self.activate(text)
            entry=dict(operation,previous={k:state[k] for k in ('rules','objects','nat')})
            next_state['history']=(state['history']+[entry])[-20:]
            atomic(self.path,json.dumps(next_state,ensure_ascii=False))
            self.journal(dict(operation,outcome='applied'))
        except Exception:
            try:
                self.activate(previous);atomic(self.path,json.dumps(state,ensure_ascii=False))
                self.journal(dict(operation,outcome='restored'))
            except Exception:
                self.journal(dict(operation,outcome='restore_failed'))
                raise ValueError('Device reload and restore failed; inspect device operation journal')
            raise
        (self.base/'ticket.json').unlink(missing_ok=True)
        return {'ok':True,'version':next_state['version']}


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(30)
        _,uid,_=struct.unpack('3i',self.connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        if uid!=65532: return
        try:
            raw=self.rfile.readline(16385)
            if len(raw)>16384 or not raw.endswith(b'\n'): raise ValueError('Request too large')
            result=self.server.device.request(json.loads(raw))
            payload={'ok':True,'data':result}
        except Conflict as e: payload={'ok':False,'status':409,'error':str(e)}
        except (ValueError,KeyError,TypeError,subprocess.TimeoutExpired) as e: payload={'ok':False,'status':400,'error':str(e)[:2000]}
        except Exception: payload={'ok':False,'status':503,'error':'Device operation failed; inspect local device service'}
        self.wfile.write(json.dumps(payload,ensure_ascii=False).encode()+b'\n')


if __name__=='__main__':
    device=Device(sys.argv[1])
    if len(sys.argv)>2 and sys.argv[2]=='init': device.initialize();sys.exit(0)
    # Keep one device operation active at a time, including across process replacement.
    lock=(device.base/'broker.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    path=Path('/run/xoc-console/api.sock');path.unlink(missing_ok=True)
    with socketserver.UnixStreamServer(str(path),Handler) as server:
        path.chmod(0o666);server.device=device;server.serve_forever()
