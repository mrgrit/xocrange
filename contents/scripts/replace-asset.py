#!/usr/bin/env python3
"""Replace one lesson image with a new PNG (re-captured on the current system).

  replace-asset.py <course dir> <old asset name> <new.png>

Assets are named by their SHA-256. The new file is added under that name, every reference in
the course (slides and manuscript sections) is switched, the course catalogue entry keeps the
old source pages, and the old file is removed. Run content-module.py manifest afterwards.
"""
import hashlib
import json
from pathlib import Path
import sys

course_dir, old, new_file = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
raw = new_file.read_bytes()
if not raw.startswith(b'\x89PNG\r\n\x1a\n') or len(raw) > 8 * 1024 ** 2:
    sys.exit('The replacement must be a PNG of at most 8 MiB.')
catalogue = course_dir / 'course.json'
course = json.loads(catalogue.read_text())
if old not in course['assets']:
    sys.exit('Unknown asset: ' + old)
name = hashlib.sha256(raw).hexdigest() + '.png'
if name == old:
    sys.exit('The replacement is identical to the current image.')
entry = dict(course['assets'].pop(old), bytes=len(raw), sha256=name[:-4])
if name in course['assets']:
    entry['source_pages'] = sorted(set(entry['source_pages']) | set(course['assets'][name]['source_pages']))
course['assets'][name] = entry
changed = 0


def switch(node):
    global changed
    if isinstance(node, dict):
        if node.get('asset') == old:
            node['asset'] = name; changed += 1
        for value in node.values():
            switch(value)
    elif isinstance(node, list):
        for value in node:
            switch(value)


for path in sorted(course_dir.glob('lessons/*/*.json')):
    document = json.loads(path.read_text())
    before = changed
    switch(document)
    if changed != before:
        path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + '\n')
if not changed:
    sys.exit('No lesson refers to that asset; nothing was changed.')
(course_dir / 'assets' / name).write_bytes(raw)
(course_dir / 'assets' / old).unlink()
catalogue.write_text(json.dumps(course, ensure_ascii=False, indent=2) + '\n')
print(json.dumps({'old': old, 'new': name, 'references': changed}))
