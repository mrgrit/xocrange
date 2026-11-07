#!/usr/bin/env python3
"""Idempotently add/remove xOC's watch rules without flushing any other rules."""
from pathlib import Path
import argparse
import shlex
import subprocess


def key(args):
    return args[args.index('-k') + 1] if '-k' in args else next((x[4:] for x in args if x.startswith('key=')), None)


def configure(path, remove=False, run=subprocess.run, output=None):
    original = [shlex.split(line) for line in Path(path).read_text().splitlines() if line and not line.startswith('#')]
    desired = []
    for args in original:
        if args[0] != '-w':
            raise ValueError('Only reviewed xOC path watches are supported')
        desired.append([args[0], str(Path(args[1]).resolve()), *args[2:]])
    existing = [shlex.split(line) for line in run(['auditctl', '-l'], capture_output=True, text=True, check=True).stdout.splitlines()]
    changes = []
    for old, args in zip(original, desired):
        found = [row for row in existing if key(row) == key(args)]
        if found and found not in ([args], [old]):
            raise ValueError('An existing xOC audit key has different rules; refusing replacement')
        changes.append((args, found))
    for args, found in changes:
        # Ubuntu 26.04 can provide commands through symlinks. A watch on the
        # link itself misses execution of its target. Migrate only our exact
        # previous rule, preserving every unrelated host audit rule.
        if found and (remove or found != [args]):
            command=['auditctl', '-W', *found[0][1:]]
            deleted=run(command,check=False,capture_output=True,text=True)
            if getattr(deleted,'returncode',0):
                # Some kernels remove a legacy symlink watch but return ENOENT
                # for the remaining audit rule variant. Verify actual state;
                # never ignore an error while the owned rule is still present.
                current=run(['auditctl','-l'],capture_output=True,text=True,check=True).stdout
                if any(key(shlex.split(line))==key(args) for line in current.splitlines()):
                    raise subprocess.CalledProcessError(deleted.returncode,command)
        if not remove and found != [args]:
            run(['auditctl', *args], check=True)
    if output is not None and not remove:
        destination = Path(output)
        if destination.is_symlink():
            raise ValueError('The managed audit rule file must not be a symlink')
        destination.write_text('\n'.join(shlex.join(args) for args in desired)+'\n')
        destination.chmod(0o600)


if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('path')
    parser.add_argument('--remove',action='store_true')
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    configure(args.path,args.remove,output=args.output)
