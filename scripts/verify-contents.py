#!/usr/bin/env python3
"""Verify the bundled Community content (contents/) against its module.json; stdlib only before bootstrap."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from xocrange.content_module import summary

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        print(json.dumps(summary(args.root)))
    except (ValueError, OSError, KeyError) as exc:
        raise SystemExit('Content bundle: ' + str(exc))
