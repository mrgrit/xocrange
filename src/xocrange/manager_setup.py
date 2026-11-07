"""Private native Manager API identities, independent of web UI selection."""
import json
import os
from pathlib import Path
import secrets
import subprocess
import yaml

from .errors import XocError
from .ui_setup import certificate, owned_volume, private_json, write

STATE=Path('/var/lib/xocrange/manager')


def prepare(engine,project,state=STATE):
    if os.geteuid()!=0:raise XocError('root_required','Manager provisioning requires root.')
    if any(p.is_symlink() for p in (state,*state.parents)):
        raise XocError('unsafe_config','Manager state cannot traverse symlinks.')
    state.mkdir(parents=True,exist_ok=True,mode=0o700)
    if state.stat().st_mode & 0o077 or state.stat().st_uid!=0:
        raise XocError('unsafe_config','Manager state must be private and owned by root.')
    path=state/'credentials.json'
    credentials=private_json(path) if path.exists() else {name:'Xoc1!'+secrets.token_urlsafe(32) for name in ('wazuh','wazuh-wui')}
    write(path,json.dumps(credentials,indent=2)+'\n')
    if not (state/'ca.pem').exists():
        subprocess.run(['openssl','req','-x509','-newkey','rsa:3072','-nodes','-days','3650','-sha256','-keyout',str(state/'ca-key.pem'),'-out',str(state/'ca.pem'),'-subj','/CN=xOC Manager CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign'],check=True,capture_output=True)
        (state/'ca-key.pem').chmod(0o600)
    certificate('siem',['siem'],state)
    config={'host':['0.0.0.0'],'port':55000,'drop_privileges':True,
            'https':{'enabled':True,'key':'siem-key.pem','cert':'siem.pem','use_ca':False},
            'cors':{'enabled':False}}
    volume=owned_volume(engine,project,'siem-config')
    volume.chmod(0o700);os.chown(volume,999,999)
    for name in ('credentials.json','ca.pem','siem.pem','siem-key.pem'):
        write(volume/name,(state/name).read_bytes(),999)
    write(volume/'api.yaml',yaml.safe_dump(config),999)
    return {'status':'prepared','api':'internal TLS only'}
