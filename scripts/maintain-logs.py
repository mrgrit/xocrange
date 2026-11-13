#!/usr/bin/env python3
import json
from xocrange.operations import operation_lock
from xocrange.log_maintenance import maintain
with operation_lock(wait=0):
    print(json.dumps(maintain()))
