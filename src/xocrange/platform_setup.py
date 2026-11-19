"""Provision the common gateway and private management volumes without SIEM."""
import json
import os
import re
from pathlib import Path
import secrets
import subprocess
import uuid
from .registry import build_registry
from .ui_setup import STATE as TLS_STATE, certificate, ensure_ca, host_rule, ingress_config, ingress_names, owned_volume, private_json, public_host, write
from .errors import XocError

STATE = Path('/var/lib/xocrange/platform')


def prepare(engine, project, root, selected, host=None, state=STATE, tls=TLS_STATE, planned=None):
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
    config.update(public_host=host, siem_available='siem-ui' in selected, consoles=[d for d in ('fw','ips','waf') if 'console-'+d in selected])
    installer_user = os.environ.get('SUDO_USER', '')
    if installer_user != 'root' and re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', installer_user):
        config.setdefault('ssh_username', installer_user)
    config.setdefault('ssh_username', None)
    config.setdefault('installation_id', str(uuid.uuid4()))
    write(path, json.dumps(config))
    ensure_ca(tls, host)
    from .entitlements import learner_domain
    domain = learner_domain(root)
    certificate('web', ingress_names(host, domain), tls)
    def volume(name, uid, gid=None, mode=0o700):
        base = owned_volume(engine, project, name)
        os.chown(base, uid, uid if gid is None else gid); base.chmod(mode)
        return base
    config_volume = volume('platform-config', 65532)
    from .entitlements import sync_platform
    sync_platform(config_volume)
    platform_config = {k:config[k] for k in ('secret_key','bootstrap_password','public_host','siem_available','consoles','ssh_username')}
    # The lab page (실습 환경) shows where to practise: target names and, when the office PC
    # or the attack terminal is selected, the lab account. The account is for the lab only.
    from .office_setup import USERNAME
    lab = {'domain': domain, 'targets': sorted({t['id'] for t in (planned or {}).get('registry', {}).get('targets', [])
                                                if not str(t.get('component_id', '')).startswith('fixture-')})}
    if {'office-pc', 'attacker'} & set(selected):
        config.setdefault('office_username', USERNAME)
        config.setdefault('office_password', secrets.token_urlsafe(12))
        write(path, json.dumps(config))
        lab.update(username=config['office_username'], password=config['office_password'])
    platform_config['lab'] = lab
    write(config_volume/'config.json', json.dumps(platform_config), 65532)
    if planned is not None:
        write(config_volume/'registry.json', json.dumps(build_registry(planned, config['installation_id'])), 65532)
    volume('platform-observation', 0, 33, 0o750)
    if 'academy-reader' in selected:
        from .content import bundle
        write(config_volume/'bundle.json', json.dumps(bundle(root)), 65532)
        (config_volume/'catalog').mkdir(mode=0o700, exist_ok=True)
        os.chown(config_volume/'catalog', 65532, 65532)
        write(config_volume/'catalog/academy.json', (root/'contents/catalog/academy.json').read_bytes(), 65532)
        from .academy_content import catalog
        import shutil
        import tempfile
        _, files = catalog(root)
        staged = Path(tempfile.mkdtemp(prefix='.academy-',dir=config_volume))
        try:
            for file in files:
                destination = staged/file.relative_to(root/'contents/academy')
                destination.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(file,destination)
            for item in [staged,*staged.rglob('*')]:
                os.chown(item,65532,65532);item.chmod(0o700 if item.is_dir() else 0o600)
            target = config_volume/'academy'
            if target.exists(): shutil.rmtree(target)
            staged.rename(target)
        finally:
            if staged.exists(): shutil.rmtree(staged)
    else:
        (config_volume/'bundle.json').unlink(missing_ok=True)
        (config_volume/'catalog/academy.json').unlink(missing_ok=True)
        import shutil
        shutil.rmtree(config_volume/'academy',ignore_errors=True)
    volume('platform-data', 65532)
    volume('platform-socket', 65532, 33, 0o770)
    for device in ('fw','ips','waf'):
        volume('console-'+device+'-state', 33 if device=='waf' else 0)
        if 'console-'+device in selected:
            volume('console-'+device+'-socket', 33 if device=='waf' else 0, 33, 0o770)
    if 'office-pc' in selected:
        from .office_setup import account
        account(volume('office-config', 0), config)
        write(path, json.dumps(config))
    if 'attacker' in selected:
        from .office_setup import account, lab_hosts
        terminal = volume('attacker-config', 0)
        account(terminal, config)       # the same lab account as the office PC
        write(terminal/'hosts', lab_hosts(planned, domain))
        write(path, json.dumps(config))
    ingress = volume('ingress-config', 65532)
    write(ingress/'haproxy.cfg', ingress_config(host), 65532)
    write(ingress/'ingress.pem', (tls/'web.pem').read_bytes()+(tls/'web-key.pem').read_bytes(), 65532)
    web = volume('web-tls', 33)
    for name, value in {'ca.pem':(tls/'ca.pem').read_bytes(), 'host-rule.conf':host_rule(host),
                        'learner-domains.json':json.dumps([domain] if domain else []),
                        'logo.png':(root/'assets/branding/xoc-range-logo.png').read_bytes()}.items():
        write(web/name, value, 33)
    write(Path('/etc/xocrange/ca.crt'), (tls/'ca.pem').read_bytes(), mode=0o644)
    return {'url':'https://'+host+'/core/', 'bootstrap_credentials':str(path)}
