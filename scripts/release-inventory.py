#!/usr/bin/env python3
"""Record installed package/image versions without container secrets or host keys."""
import importlib.metadata
import json
from pathlib import Path
import platform
import re
import subprocess
import sys
from xocrange.operations import save, timestamp

release, plan = Path(sys.argv[1]), sys.argv[2]
directory = release/'.local/plans'/plan
def run(args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=60)
    return p.stdout.strip() if p.returncode == 0 else None

images = json.loads((directory/'images.lock.json').read_text())
value = {'schema_version':'xoc.release-inventory/0.1.0','created_at':timestamp(), 'release_sha256':release.name,
         'plan_id':images['plan_id'], 'os':run(['lsb_release','-ds']), 'architecture':platform.machine(),
         'kernel':platform.release(), 'python':platform.python_version(),
         'docker':run(['docker','version','--format','{{.Server.Version}}']),
         'compose':run(['docker','compose','version','--short']), 'images':images['services'],
         'python_packages':sorted([{'name':d.metadata['Name'],'version':d.version} for d in importlib.metadata.distributions()],key=lambda d:d['name'].lower()),
         'host_packages':run(['dpkg-query','-W','-f=${binary:Package}\t${Version}\n']).splitlines(), 'containers':{},
         'base_images':sorted({line.split()[1] for p in release.rglob('*Dockerfile*') if p.is_file() for line in p.read_text().splitlines() if line.startswith('FROM ')}),
         'distribution_license':'pending-explicit-release-decision'}
for name in images['services']:
    container = 'xoc-core-security-path-'+name+'-1'
    packages = None
    for command in (['dpkg-query','-W','-f=${binary:Package}\t${Version}\n'], ['rpm','-qa','--qf','%{NAME}\t%{VERSION}-%{RELEASE}\n'], ['apk','info','-v']):
        packages = run(['docker','exec',container,*command])
        if packages is not None: break
    value['containers'][name] = {'packages':packages.splitlines() if packages else []}
save(Path('/var/lib/xocrange/release-inventory.json'), value)
print(json.dumps({'status':'recorded','images':len(images['services']),'host_packages':len(value['host_packages']), 'path':'/var/lib/xocrange/release-inventory.json'}))
