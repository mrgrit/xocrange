#!/usr/bin/env python3
"""Installer-internal operations. install.sh already owns the appliance lock."""
import argparse
import json
from pathlib import Path
from xocrange import operations

p = argparse.ArgumentParser()
p.add_argument('action', choices=['checkpoint', 'rollback', 'restore'])
p.add_argument('path', type=Path)
args = p.parse_args()
if args.action == 'checkpoint':
    result = operations.create(args.path, portable=False, keep_stopped=True)
else:
    result = operations.restore(args.path, checkpoint=args.action == 'restore')
print(json.dumps(result, indent=2))
