#!/usr/bin/env python3
"""Installer entry point: register the office PC's agent once the Manager answers."""
import json
from pathlib import Path
import sys

from xocrange.lab import Docker, checked_plan
from xocrange.manager_api import ManagerClient
from xocrange.office_setup import agent_key

root = Path(sys.argv[1])
directory, plan = checked_plan(root, sys.argv[2])
selected = plan['lock']['selected']
if 'office-pc' in selected and 'siem' in selected:
    project = plan['compose']['name']
    engine = Docker(directory/'compose.yaml', project)
    print(json.dumps(agent_key(engine, project, ManagerClient(engine, project))))
