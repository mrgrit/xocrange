"""Provision the common gateway and private management volumes without SIEM."""
import json
import os
from pathlib import Path
import secrets
import subprocess
from .ui_setup import STATE as TLS_STATE, certificate, host_rule, ingress_config, owned_volume, private_json, public_host, write
from .errors import XocError

STATE = Path('/var/lib/xocrange/platform')


def prepare(engine, project, root, selected, host=None, state=STATE, tls=TLS_STATE):
    if os.geteuid() != 0:
        raise XocError('root_required', 'Platform provisioning requires the installer.')
    for directory in (state, tls):
        if any(p.is_symlink() for p in (directory, *directory.parents)):
            raise XocError('unsafe_config', 'Private platform paths cannot traverse symlinks.')
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if directory.stat().st_mode & 0o077:
            raise XocError('unsafe_config', 'Platform state must be private.')
    path = state/'credentials.json'
    config = private_json(path) if path.exists() else {'secret_key': secrets.token_urlsafe(64), 'bootstrap_password': secrets.token_urlsafe(32)}
    previous = private_json(tls/'credentials.json').get('public_host') if (tls/'credentials.json').exists() else None
    host = public_host(host or config.get('public_host') or previous or json.loads(subprocess.check_output(['ip','-j','-4','route','get','1.1.1.1'],text=True))[0]['prefsrc'])
    config.update(public_host=host, siem_available='siem-ui' in selected)
    write(path, json.dumps(config))
    if not (tls/'ca.pem').exists():
        subprocess.run(['openssl','req','-x509','-newkey','rsa:3072','-nodes','-days','3650','-sha256','-keyout',str(tls/'ca-key.pem'),'-out',str(tls/'ca.pem'),'-subj','/CN=xOC Range local CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign'],check=True,capture_output=True)
        (tls/'ca-key.pem').chmod(0o600)
    certificate('web', list(dict.fromkeys([host, 'localhost', '127.0.0.1'])), tls)
    def volume(name, uid, gid=None, mode=0o700):
        base = owned_volume(engine, project, name)
        os.chown(base, uid, uid if gid is None else gid); base.chmod(mode)
        return base
    config_volume = volume('platform-config', 65532)
    write(config_volume/'config.json', json.dumps({k:config[k] for k in ('secret_key','bootstrap_password','public_host','siem_available')}), 65532)
    volume('platform-data', 65532)
    volume('platform-socket', 65532, 33, 0o770)
    ingress = volume('ingress-config', 65532)
    write(ingress/'haproxy.cfg', ingress_config(host), 65532)
    write(ingress/'ingress.pem', (tls/'web.pem').read_bytes()+(tls/'web-key.pem').read_bytes(), 65532)
    web = volume('web-tls', 33)
    for name, value in {'ca.pem':(tls/'ca.pem').read_bytes(), 'host-rule.conf':host_rule(host),
                        'logo.png':(root/'assets/branding/xoc-range-logo.png').read_bytes()}.items():
        write(web/name, value, 33)
    write(Path('/etc/xocrange/ca.crt'), (tls/'ca.pem').read_bytes(), mode=0o644)
    return {'url':'https://'+host+'/core/', 'bootstrap_credentials':str(path)}
