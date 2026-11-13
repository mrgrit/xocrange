#!/usr/bin/env python3
"""Check that Core artifacts carry no paid-module functionality (K12 G1 boundary).

Source only:      python3 scripts/check-boundary.py
Installed (root): sudo xoc-python scripts/check-boundary.py --installed
"""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from xocrange.boundary import check  # noqa: E402

parser = argparse.ArgumentParser()
parser.add_argument('--root', type=Path, default=ROOT)
parser.add_argument('--installed', action='store_true',
                    help='also check the installed release inventory and planned Compose file')
args = parser.parse_args()
inventory, compose = None, []
if args.installed:
    state = Path('/var/lib/xocrange')
    install = json.loads((state / 'last-install.json').read_text())
    inventory = state / 'release-inventory.json'
    plan = Path(install['release']) / '.local/plans' / install['plan']
    compose = [p for p in (plan / 'compose.yaml', plan / 'compose.images.yaml') if p.is_file()]
report = check(args.root, inventory, compose)
print(json.dumps(report, indent=2))
sys.exit(0 if report['status'] == 'passed' else 1)
