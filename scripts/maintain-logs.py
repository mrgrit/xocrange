#!/usr/bin/env python3
"""Per-minute log rotation and retention (xocrange-log-maintenance.timer).

While an install, update, backup or restore holds the operation lock this run
is skipped, not failed: the next minute retries, and the unit must not show as
failed in `systemctl --failed` during every update.
"""
import json
from xocrange.errors import XocError
from xocrange.operations import operation_lock
from xocrange.log_maintenance import maintain
try:
    with operation_lock(wait=0):
        print(json.dumps(maintain()))
except XocError as exc:
    if exc.code != 'operation_busy':
        raise
    print(json.dumps({'status': 'skipped', 'reason': 'operation_busy'}))
