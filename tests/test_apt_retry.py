import os
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]


def exercise(tmp_path,mode):
    # Run the actual installer function with a fake apt command. The function is
    # exported to install-telemetry.sh by the parent installer in production.
    script=(ROOT/'install.sh').read_text()
    function=script[script.index('apt_retry() {'):script.index('export -f apt_retry')]
    apt=tmp_path/'apt-get';apt.write_text('''#!/usr/bin/env python3
import os,pathlib,sys
p=pathlib.Path(os.environ['ATTEMPTS']);n=int(p.read_text())+1 if p.exists() else 1;p.write_text(str(n))
mode=os.environ['APT_CASE']
if mode=='once' and n>1:sys.exit(0)
print('E: Package not found' if mode=='other' else 'E: Could not get lock /var/lib/apt/lists/lock')
sys.exit(100)
''');apt.chmod(0o755)
    sleep=tmp_path/'sleep';sleep.write_text('#!/bin/sh\nexit 0\n');sleep.chmod(0o755)
    env={**os.environ,'PATH':str(tmp_path)+':'+os.environ['PATH'],'ATTEMPTS':str(tmp_path/'attempts'),'APT_CASE':mode}
    r=subprocess.run(['bash','-c',function+'\napt_retry update'],env=env,capture_output=True,text=True)
    return r,int((tmp_path/'attempts').read_text())


def test_waits_for_lists_lock_then_retries(tmp_path):
    result,count=exercise(tmp_path,'once')
    assert result.returncode==0 and count==2
    assert 'waiting for its lock' in result.stdout


def test_other_apt_errors_are_not_hidden_or_retried(tmp_path):
    result,count=exercise(tmp_path,'other')
    assert result.returncode==100 and count==1


def test_lock_wait_is_bounded(tmp_path):
    result,count=exercise(tmp_path,'always')
    assert result.returncode==100 and count==30
