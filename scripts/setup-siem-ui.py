#!/usr/bin/env python3
"""Installer/boot entry point; only the selected, validated UI may be provisioned."""
import json
from pathlib import Path
import sys

from xocrange.indexer import Client, initialize
from xocrange.lab import Docker, checked_plan
from xocrange.ui_setup import prepare

root=Path(sys.argv[2])
directory,plan=checked_plan(root,sys.argv[3])
if 'siem-ui' not in plan['lock']['selected']:
    raise SystemExit(0)
engine=Docker(directory/'compose.yaml',plan['compose']['name'])
if sys.argv[1]=='prepare':
    result=prepare(engine,plan['compose']['name'],sys.argv[4] if len(sys.argv)>4 and sys.argv[4] else None,root=root)
elif sys.argv[1]=='initialize':
    result=initialize(Client(engine,plan['compose']['name'],user='admin'),root)
else:
    raise SystemExit('Expected prepare or initialize')
print(json.dumps(result))
