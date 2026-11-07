#!/usr/bin/env python3
"""Idempotently add/remove xOC's watch rules without flushing any other rules."""
from pathlib import Path
import shlex
import subprocess
import sys


def key(args):
    return args[args.index('-k') + 1] if '-k' in args else next((x[4:] for x in args if x.startswith('key=')), None)


def configure(path, remove=False, run=subprocess.run):
    desired = [shlex.split(line) for line in Path(path).read_text().splitlines() if line and not line.startswith('#')]
    existing = [shlex.split(line) for line in run(['auditctl', '-l'], capture_output=True, text=True, check=True).stdout.splitlines()]
    for args in desired:
        found = [row for row in existing if key(row) == key(args)]
        if found and found != [args]:
            raise ValueError('An existing xOC audit key has different rules; refusing replacement')
        if remove and found:
            run(['auditctl', '-W', *args[1:]], check=True)
        elif not remove and not found:
            run(['auditctl', *args], check=True)


if __name__ == '__main__':
    configure(sys.argv[1], '--remove' in sys.argv[2:])
