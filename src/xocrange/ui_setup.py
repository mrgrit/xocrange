"""Per-install identities, TLS and narrowly owned SIEM UI configuration volumes."""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess

import bcrypt
import yaml

from .errors import XocError

STATE = Path('/var/lib/xocrange/ui')


def public_host(value):
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError:
        if re.fullmatch(r'[0-9.]+',value):
            raise XocError('invalid_public_host','Invalid IPv4 address.')
        if len(value) <= 253 and re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*', value):
            return value.lower()
        raise XocError('invalid_public_host', 'Use an IPv4 address or DNS hostname without a scheme, port or path.')


def private_json(path):
    if any(p.is_symlink() for p in (path, *path.parents)) or path.stat().st_mode & 0o077 or path.stat().st_uid != os.geteuid():
        raise XocError('unsafe_credentials', 'SIEM credentials must be a private, locally owned file.')
    return json.loads(path.read_text())


def write(path, data, uid=0, mode=0o600):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise XocError('unsafe_config', 'Configuration paths must not traverse symlinks.')
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    os.chmod(path, mode)
    os.chown(path, uid, uid)


def owned_volume(engine, project, name):
    full = project + '_' + name
    names = engine.run(['volume', 'ls', '--format', '{{.Name}}']).splitlines()
    if full not in names:
        engine.run(['volume', 'create', '--label', 'com.docker.compose.project='+project,
                    '--label', 'com.docker.compose.volume='+name, full])
    item, = json.loads(engine.run(['volume', 'inspect', full]))
    labels = item.get('Labels') or {}
    path = Path(item['Mountpoint'])
    if item.get('Driver') != 'local' or item.get('Options') or labels.get('com.docker.compose.project') != project or labels.get('com.docker.compose.volume') != name or not path.is_absolute() or any(p.is_symlink() for p in (path, *path.parents)):
        raise XocError('untrusted_ui_volume', 'Refusing an unrelated or redirected SIEM configuration volume.')
    return path


def indexer_config():
    cfg = {'network.host':'0.0.0.0','node.name':'indexer','cluster.name':'xoc-siem',
           'path.data':'/var/lib/wazuh-indexer','path.logs':'/var/log/wazuh-indexer',
           'discovery.type':'single-node','plugins.security.ssl.http.enabled':True,
           'plugins.security.ssl.transport.enforce_hostname_verification':True,
           'plugins.security.ssl.transport.resolve_hostname':False,
           'plugins.security.authcz.admin_dn':['CN=xoc-indexer-admin'],
           'plugins.security.nodes_dn':['CN=indexer'],
           'plugins.security.restapi.roles_enabled':['all_access'],
           'plugins.security.allow_default_init_securityindex':True}
    for layer in ('http','transport'):
        for name, value in [('pemcert_filepath','indexer.pem'),('pemkey_filepath','indexer-key.pem'),('pemtrustedcas_filepath','ca.pem')]:
            cfg[f'plugins.security.ssl.{layer}.{name}'] = 'certs/'+value
    return cfg


def writer_role():
    return {'reserved':False,'cluster_permissions':['cluster_composite_ops'],
            'index_permissions':[{'index_patterns':['xoc-events-*','wazuh-alerts-4.x-*'],
            'allowed_actions':['indices:admin/create','indices:admin/mapping/put','indices:data/write/index*','indices:data/write/bulk*']}]}


def dashboard_config(credentials):
    return {'server.host':'0.0.0.0','server.port':5601,'server.name':'xOC Range SIEM',
            'server.basePath':'/siem','server.rewriteBasePath':True,
            'server.ssl.enabled':True,'server.ssl.certificate':'/run/xoc-secrets/dashboard.pem',
            'server.ssl.key':'/run/xoc-secrets/dashboard-key.pem',
            'opensearch.hosts':['https://indexer:9200'],'opensearch.ssl.verificationMode':'full',
            'opensearch.ssl.certificateAuthorities':['/run/xoc-secrets/ca.pem'],
            'opensearch.username':'kibanaserver','opensearch.password':credentials['kibanaserver'],
            'opensearch.requestHeadersAllowlist':['authorization','securitytenant'],
            'opensearch_security.multitenancy.enabled':False,
            'opensearch_security.cookie.secure':True,'opensearch_security.cookie.password':credentials['cookie'],
            'opensearch_security.session.ttl':3600000,'opensearch_security.session.keepalive':True,
            'opensearch_security.auth.type':'basicauth','server.maxPayloadBytes':1048576,
            'opensearchDashboards.branding':{'logo':{'defaultUrl':'/assets/xoc-range-logo.png'},'mark':{'defaultUrl':'/assets/xoc-range-logo.png'},'loadingLogo':{'defaultUrl':'/assets/xoc-range-logo.png'},'applicationTitle':'xOC Range SIEM'},
            'data.search.usageTelemetry.enabled':False,
            'uiSettings.overrides':{'defaultRoute':'/app/dashboards#/view/xoc-overview','defaultIndex':'xoc-events'}}


def ingress_config(host):
    host = public_host(host)
    return f'''global
    log stdout format raw local0
    maxconn 512
defaults
    log global
    timeout connect 5s
    timeout client 180s
    timeout server 180s
frontend http
    bind :8080
    mode http
    http-request redirect prefix https://{host} code 308
frontend https
    bind :8443 ssl crt /run/xoc-secrets/ingress.pem ssl-min-ver TLSv1.2
    mode http
    http-request deny deny_status 400 if {{ path_beg /core/ }} {{ query -m found }}
    http-request deny deny_status 400 if {{ path_beg /core/ }} {{ req.hdr(authorization) -m found }}
    http-request set-header X-Xoc-Client-IP %[src]
    http-request set-header X-Forwarded-Proto https
    http-request del-header X-Forwarded-For
    http-request del-header X-Forwarded-Host
    default_backend security_path
backend security_path
    mode http
    server fw 172.29.10.1:8443
'''


def ingress_names(host):
    """Names served by the TLS ingress: the access address plus the hosts-only
    learner domain for selected practice targets (<id>.xoc.range)."""
    return list(dict.fromkeys([host, 'localhost', '127.0.0.1', 'xoc.range', '*.xoc.range']))


def host_rule(host):
    # IP access is the installer default, not an attack. Keep this CRS exception
    # inside the SIEM vhost and limited to its known addresses and path prefix.
    names='|'.join(re.escape(x) for x in dict.fromkeys([public_host(host),'127.0.0.1']))
    return ('SecRule REQUEST_URI "@rx ^/(?:siem|core)(?:/|$)" "id:110089,phase:1,pass,nolog,t:none,chain"\n'
            f'    SecRule REQUEST_HEADERS:Host "@rx ^(?:{names})(?::[0-9]+)?$" "t:none,t:lowercase,ctl:ruleRemoveById=920350"\n')


def certificate(name, names, state=STATE):
    cert, key = state/(name+'.pem'), state/(name+'-key.pem')
    stamp = state/(name+'-names.json')
    if cert.exists() and key.exists() and stamp.exists() and json.loads(stamp.read_text()) == names:
        if subprocess.run(['openssl','x509','-checkend',str(30*86400),'-noout','-in',str(cert)],capture_output=True).returncode == 0:
            return
    extensions = ['basicConstraints=critical,CA:FALSE','keyUsage=critical,digitalSignature,keyEncipherment','extendedKeyUsage=serverAuth,clientAuth']
    if names:
        sans=[]
        for value in names:
            try: ipaddress.ip_address(value); kind='IP'
            except ValueError: kind='DNS'
            sans.append(kind+':'+value)
        extensions.append('subjectAltName='+','.join(sans))
    ext = state/(name+'.ext'); ext.write_text('\n'.join(extensions)+'\n')
    csr=state/(name+'.csr')
    subprocess.run(['openssl','req','-new','-newkey','rsa:3072','-nodes','-keyout',str(key),'-out',str(csr),'-subj','/CN='+name],check=True,capture_output=True)
    subprocess.run(['openssl','x509','-req','-in',str(csr),'-CA',str(state/'ca.pem'),'-CAkey',str(state/'ca-key.pem'),'-set_serial',str(secrets.randbits(128)),'-days','397','-sha256','-extfile',str(ext),'-out',str(cert)],check=True,capture_output=True)
    for p in (cert,key): p.chmod(0o600)
    stamp.write_text(json.dumps(names)); stamp.chmod(0o600)
    csr.unlink();ext.unlink()


def prepare(engine, project, host=None, state=STATE, root=None):
    if os.geteuid() != 0:
        raise XocError('root_required', 'UI provisioning needs the privileged installer.')
    if any(p.is_symlink() for p in (state,*state.parents)):
        raise XocError('unsafe_config','UI state cannot traverse symlinks.')
    state.mkdir(mode=0o700,parents=True,exist_ok=True)
    if state.stat().st_mode & 0o077:
        raise XocError('unsafe_config','UI state must be private.')
    path=state/'credentials.json'
    credentials=private_json(path) if path.exists() else {name:secrets.token_urlsafe(32) for name in ('admin','kibanaserver','xoc-writer','cookie')}
    host=public_host(host or credentials.get('public_host') or json.loads(subprocess.check_output(['ip','-j','-4','route','get','1.1.1.1'],text=True))[0]['prefsrc'])
    credentials['public_host']=host
    write(path,json.dumps(credentials,indent=2)+'\n')
    if not (state/'ca.pem').exists():
        subprocess.run(['openssl','req','-x509','-newkey','rsa:3072','-nodes','-days','3650','-sha256','-keyout',str(state/'ca-key.pem'),'-out',str(state/'ca.pem'),'-subj','/CN=xOC Range local CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign'],check=True,capture_output=True)
        (state/'ca-key.pem').chmod(0o600)
    for name, names in [('indexer',['indexer']),('dashboard',['dashboard']),('web',ingress_names(host)),('xoc-indexer-admin',[])]:
        certificate(name,names,state)
    def populate(volume, uid, files):
        base=owned_volume(engine,project,volume)
        base.chmod(0o700);os.chown(base,uid,uid)
        for name,value in files.items():
            write(base/name,yaml.safe_dump(value,sort_keys=False) if isinstance(value,dict) else value,uid)
        for directory in base.rglob('*'):
            if directory.is_dir(): directory.chmod(0o700);os.chown(directory,uid,uid)
    users={'_meta':{'type':'internalusers','config_version':2}}
    for user in ('admin','kibanaserver','xoc-writer'):
        users[user]={'hash':bcrypt.hashpw(credentials[user].encode(),bcrypt.gensalt(rounds=12)).decode(),'reserved':True,'backend_roles':['admin'] if user=='admin' else []}
    mapping={'_meta':{'type':'rolesmapping','config_version':2},'all_access':{'backend_roles':['admin']},'kibana_server':{'users':['kibanaserver']},'xoc_ingest':{'users':['xoc-writer']}}
    writer={'xoc_ingest':writer_role()}
    populate('indexer-config',1000,{'opensearch.yml':indexer_config(),'certs/ca.pem':(state/'ca.pem').read_bytes(),'certs/indexer.pem':(state/'indexer.pem').read_bytes(),'certs/indexer-key.pem':(state/'indexer-key.pem').read_bytes(),'opensearch-security/internal_users.yml':users,'opensearch-security/roles_mapping.yml':mapping,'roles-extra.yml':writer})
    from .manager_setup import STATE as manager_state
    manager_credentials=private_json(manager_state/'credentials.json')
    populate('dashboard-config',1000,{'dashboard.yml':dashboard_config(credentials),'ca.pem':(state/'ca.pem').read_bytes(),'dashboard.pem':(state/'dashboard.pem').read_bytes(),'dashboard-key.pem':(state/'dashboard-key.pem').read_bytes(),'manager-ca.pem':(manager_state/'ca.pem').read_bytes(),'manager-api.json':json.dumps({'username':'wazuh-wui','password':manager_credentials['wazuh-wui']})})
    dashboard_data=owned_volume(engine,project,'dashboard-data')
    dashboard_data.chmod(0o700);os.chown(dashboard_data,1000,1000)
    native={'hosts':[{'xoc':{'url':'https://siem','port':55000,'username':'wazuh-wui','password':manager_credentials['wazuh-wui'],'run_as':True}}]}
    for relative in ('wazuh','wazuh/config','wazuh/logs'):
        directory=dashboard_data/relative
        if directory.is_symlink():raise XocError('unsafe_config','Dashboard data must not redirect managed paths.')
        directory.mkdir(mode=0o700,exist_ok=True);os.chown(directory,1000,1000)
    write(dashboard_data/'wazuh/config/wazuh.yml',yaml.safe_dump(native),1000)
    web_files={'ca.pem':(state/'ca.pem').read_bytes(),'host-rule.conf':host_rule(host)}
    if root is not None:
        web_files['logo.png']=(root/'assets/branding/xoc-range-logo.png').read_bytes()
    populate('web-tls',33,web_files)
    web_volume=owned_volume(engine,project,'web-tls')
    for obsolete in ('web.pem','web-key.pem'):
        (web_volume/obsolete).unlink(missing_ok=True)
    # TLS ends before the routed IPS path so Suricata can inspect HTTP as well
    # as WAF. The backend Dashboard connection is separately TLS-verified.
    populate('ingress-config',65532,{'haproxy.cfg':ingress_config(host),'ingress.pem':(state/'web.pem').read_bytes()+(state/'web-key.pem').read_bytes()})
    write(Path('/etc/xocrange/ca.crt'),(state/'ca.pem').read_bytes(),mode=0o644)
    return {'url':'https://'+host+'/siem/','credentials':str(path)}
