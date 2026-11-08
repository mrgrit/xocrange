#!/usr/bin/env python3
"""Validate edited scenario YAML, then emit the public learning catalog."""
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from xocrange.livefire_content import public_catalog
root=Path(__file__).resolve().parents[1]
value=public_catalog(root)
course_path=root/'contents/academy/wazuh-threat-hunting/course.json'
course=json.loads(course_path.read_text());course['scenario_catalog']='scenarios.json'
course_path.write_text(json.dumps(course,ensure_ascii=False,indent=2)+'\n')
target=root/'contents/academy/wazuh-threat-hunting/scenarios.json'
target.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')
print(json.dumps({'scenarios':len(value['scenarios']),'missions':sum(len(s['missions']) for s in value['scenarios']),'subjects':len(value['subjects'])}))
