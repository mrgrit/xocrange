#!/usr/bin/env python3
"""Provision selected native Manager, including when web UI is excluded."""
from pathlib import Path
import json
import sys
import time
from xocrange.errors import XocError
from xocrange.lab import Docker, checked_plan
from xocrange.manager_setup import prepare

root=Path(sys.argv[1]);directory,plan=checked_plan(root,sys.argv[2])
if 'siem' in plan['lock']['selected']:
    engine=Docker(directory/'compose.yaml',plan['compose']['name'])
    if len(sys.argv)>3 and sys.argv[3]=='check':
        from xocrange.manager_api import ManagerClient
        client=ManagerClient(engine,plan['compose']['name']);deadline=time.monotonic()+120
        while True:
            try:
                token=client.authenticate()
                code,status=client.request('GET','/manager/status',token=token)
                daemons=status.get('data',{}).get('affected_items',[{}])[0]
                if code==200 and all(daemons.get(name)=='running' for name in ('wazuh-analysisd','wazuh-db','wazuh-execd','wazuh-remoted','wazuh-logcollector','wazuh-modulesd','wazuh-syscheckd')):break
            except XocError:pass
            if time.monotonic()>=deadline:raise XocError('manager_not_ready','Native Manager API and required daemons did not become ready.')
            time.sleep(3)
        print(json.dumps({'status':'ready','manager_api':'TLS verified','required_daemons':'running'}))
    else:print(json.dumps(prepare(engine,plan['compose']['name'])))
