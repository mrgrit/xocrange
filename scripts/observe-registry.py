#!/usr/bin/env python3
"""Publish bounded, sanitized host observations to the read-only platform volume."""
import json
import os
from pathlib import Path
import sys
from xocrange.lab import Docker, checked_plan
from xocrange.registry import observe
from xocrange.ui_setup import owned_volume

if os.geteuid() != 0:
    raise SystemExit('Installer-owned host observer requires root')
directory, planned = checked_plan(Path(sys.argv[1]), sys.argv[2])
engine = Docker(directory/'compose.yaml', planned['compose']['name'])
config = owned_volume(engine, planned['compose']['name'], 'platform-config')
output = owned_volume(engine, planned['compose']['name'], 'platform-observation')
registry = json.loads((config/'registry.json').read_text())
if registry['plan_id'] != planned['lock']['plan_id']:
    raise SystemExit('Registry belongs to a different installation plan')
value = observe(engine, planned['compose']['name'], registry)
temporary = output/'health.tmp'
with temporary.open('w') as stream:
    json.dump(value, stream); stream.flush(); os.fsync(stream.fileno())
os.chown(temporary, 0, 33); temporary.chmod(0o640)
temporary.replace(output/'health.json')
