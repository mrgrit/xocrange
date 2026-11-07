"""Initialize native Manager state before exposing its API; never reset its DB."""
import json
from pathlib import Path
import shutil
import os
import sys

root=Path('/var/ossec')
seed=Path('/opt/xoc-manager-seed')
for relative in ('etc','api/configuration','queue','var'):
    target=root/relative
    target.mkdir(parents=True,exist_ok=True)
    marker=target/'.xoc-initialized'
    if not marker.exists():
        if any(target.iterdir()):
            raise SystemExit('Uninitialized Manager volume is not empty: '+relative)
        shutil.copytree(seed/relative,target,dirs_exist_ok=True,symlinks=True)
        marker.touch()
    for path in [target,*target.rglob('*')]:
        if not path.is_symlink():os.chown(path,999,999)
for source,destination in [('ossec.conf','etc/ossec.conf'),('c1-decoder.xml','etc/xoc-decoders/xoc-c1.xml'),('c1-rules.xml','etc/xoc-rules/xoc-c1.xml')]:
    path=root/destination;path.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile('/opt/xoc-config/'+source,path)
    os.chown(path,0,999);path.chmod(0o640)
shutil.copyfile('/run/xoc-manager/api.yaml',root/'api/configuration/api.yaml')
os.chown(root/'api/configuration/api.yaml',999,999)
for name in ('siem.pem','siem-key.pem'):
    target=root/'api/configuration/ssl'/name
    shutil.copyfile('/run/xoc-manager/'+name,target)
    os.chown(target,999,999);target.chmod(0o600)
sys.path.append(str(root/'framework'))
from wazuh.rbac.orm import check_database_integrity, AuthenticationManager
from wazuh.security import get_users
check_database_integrity()
users={u['username']:u['id'] for u in get_users().affected_items}
secrets=json.loads(Path('/run/xoc-manager/credentials.json').read_text())
with AuthenticationManager() as auth:
    for username in ('wazuh','wazuh-wui'):
        auth.update_user(user_id=users[username],password=secrets[username])
