#!/usr/bin/env python3
import json
from pathlib import Path
import sys
from xocrange.image_lock import capture
print(json.dumps(capture(Path(sys.argv[1])), indent=2))
