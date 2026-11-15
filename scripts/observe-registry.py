#!/usr/bin/env python3
"""Publish bounded, sanitized host observations to the read-only platform volume."""
import json
import os
from pathlib import Path
import sys
from xocrange.lab import Docker, checked_plan
from xocrange.registry import observe
from xocrange.network_view import observe_network
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


def publish(name, value):
    temporary = output/(name + '.tmp')
    with temporary.open('w') as stream:
        json.dump(value, stream); stream.flush(); os.fsync(stream.fileno())
    os.chown(temporary, 0, 33); temporary.chmod(0o640)
    temporary.replace(output/(name + '.json'))


publish('health', observe(engine, planned['compose']['name'], registry))
# Lab switches and routing for the datacenter view (ADR 0010); never blocks the service health.
try:
    network = observe_network(engine, planned['compose']['name'], registry['plan_id'])
except Exception as exc:  # noqa: BLE001 - publish an explicit unavailable state instead
    network = {'schema_version': 'xoc.network/0.1.0', 'plan_id': registry['plan_id'], 'unavailable': type(exc).__name__}
publish('network', network)
