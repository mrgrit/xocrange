"""Health stays available in bootstrap; management exists only after provisioning."""
import os
from pathlib import Path
import subprocess

if not Path('/run/xoc-platform/config.json').is_file():
    os.execvp('python', ['python', '-B', '/app/health.py'])
os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'
import django
django.setup()
from django.core.management import call_command
from django.contrib.auth.models import User
from django.conf import settings
from django.db import transaction
from control.models import Profile, DevicePolicy

call_command('migrate', verbosity=0)
with transaction.atomic():
    if not User.objects.exists():
        user = User.objects.create_user('admin', password=settings.CONFIG['bootstrap_password'])
        Profile.objects.create(user=user, role='admin')
    for name in ('fw', 'ips', 'waf'):
        DevicePolicy.objects.get_or_create(device=name)
subprocess.Popen(['python', '-B', '/app/health.py'])
os.execvp('gunicorn', ['gunicorn', '--bind', 'unix:/run/xoc-platform-socket/api.sock', '--umask', '007',
                     '--workers', '2', '--threads', '2', '--timeout', '30', '--worker-tmp-dir', '/tmp',
                     '--access-logfile', '/dev/null', '--error-logfile', '/dev/null', 'wsgi:application'])
