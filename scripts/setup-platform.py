#!/usr/bin/env python3
import json
from pathlib import Path
import sys
from xocrange.lab import Docker, checked_plan
from xocrange.platform_setup import prepare

root = Path(sys.argv[1])
directory, plan = checked_plan(root, sys.argv[2])
if 'management' in plan['lock']['selected']:
    engine = Docker(directory/'compose.yaml', plan['compose']['name'])
    print(json.dumps(prepare(engine, plan['compose']['name'], root, plan['lock']['selected'], sys.argv[3] if len(sys.argv)>3 else None)))
