"""Office PC provisioning (ADR 0012): the lab account before start, the agent key after the Manager is up."""
import os
from pathlib import Path
import secrets
import shutil
import subprocess

from .errors import XocError
from .ui_setup import owned_volume, write

AGENT = 'office-pc01'
USERNAME = 'student'
STATE = Path('/var/lib/xocrange/platform/office-agent')


def account(volume, config):
    """Give the PC its lab account: a name and a SHA-512 crypt hash. The password itself
    stays in Core's private state (`sudo xoc platform credentials`)."""
    config.setdefault('office_username', USERNAME)
    config.setdefault('office_password', secrets.token_urlsafe(12))
    hashed = subprocess.run(['openssl', 'passwd', '-6', '-stdin'], input=config['office_password'], text=True,
                            capture_output=True, check=True).stdout.strip()
    if not hashed.startswith('$6$'):
        raise XocError('office_account', 'Could not prepare the office PC account.')
    write(volume/'username', config['office_username'] + '\n')
    write(volume/'password.hash', hashed + '\n')


def agent_key(engine, project, client, state=STATE):
    """Register the PC with the Manager and hand it its key. The PC starts its agent when
    the key appears in its configuration volume."""
    from .agents import enroll
    if os.geteuid() != 0:
        raise XocError('root_required', 'Agent keys may only be provisioned by the installer.')
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = state/'client.keys'
    try:
        result = enroll(client, AGENT, key)
    except XocError as error:
        if error.code != 'agent_key_conflict':
            raise
        # The Manager's registrations were reset (a restore or a clear): take its new key.
        key.unlink()
        result = enroll(client, AGENT, key)
    volume = owned_volume(engine, project, 'office-config')
    staged = volume/'.client.keys'
    shutil.copyfile(key, staged)
    os.chown(staged, 0, 0); staged.chmod(0o600)
    staged.replace(volume/'client.keys')
    return {'agent': result['id'], 'name': AGENT}
