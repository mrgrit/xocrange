#!/usr/bin/env python3
"""Install the pinned external content module; stdlib only before bootstrap."""
import argparse
from pathlib import Path
import sys
import json
import tarfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from xocrange.content_module import fetch

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--verify-only', action='store_true')
    parser.add_argument('--archive', type=Path, help='Use a local pinned archive for an offline installation')
    args = parser.parse_args()
    try:
        print(json.dumps(fetch(args.root, verify_only=args.verify_only, archive=args.archive)))
    except (ValueError, OSError, tarfile.TarError) as exc:
        raise SystemExit('Content module: ' + str(exc))
