"""Core admin password for login-gated acceptance runs.

The installer stores only the bootstrap password (and the one it sets itself
in module_lifecycle). After an operator changes it, give the current password
in a private file named by XOC_ADMIN_PASSWORD_FILE and delete the file after
the run. Never pass it as an argument or inline in a shell command: Sysmon
records every command line into the SIEM store.
"""
import os
from pathlib import Path
import stat


def admin_password(secret):
    name = os.environ.get('XOC_ADMIN_PASSWORD_FILE')
    if not name:
        return secret.get('admin_password', secret['bootstrap_password'])
    path = Path(name)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise SystemExit('XOC_ADMIN_PASSWORD_FILE must name a private regular file (mode 0600).')
    value = path.read_text().rstrip('\n')
    if not value:
        raise SystemExit('XOC_ADMIN_PASSWORD_FILE is empty.')
    return value
