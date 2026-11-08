"""Validate an explicit content package before copying it into the read-only reader."""
import hashlib
from pathlib import Path
import re
from .documents import json_document, read_bytes, within
from .errors import XocError


def catalog(root):
    root = root.resolve()
    base = root/'contents/academy'
    courses = []; files = []
    if not base.is_dir():
        raise XocError('academy_missing', 'The selected reader requires its declared content catalog.')
    for path in sorted(base.glob('*/course.json')):
        package = path.parent
        if package.is_symlink(): raise XocError('academy_path', 'Content cannot traverse symlinks.')
        course = json_document(read_bytes(path)); cid = course.get('id', '')
        if not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', cid) or cid != package.name or course.get('schema_version') != 'xoc.academy/0.1.0':
            raise XocError('academy_catalog', 'Invalid course identity.')
        if course.get('commercial') is not False or course.get('minimum_tier') != 'community':
            raise XocError('academy_tier', 'This Core bundle importer accepts explicitly free content only.')
        if not isinstance(course.get('lessons'), list) or not 1 <= len(course['lessons']) <= 200:
            raise XocError('academy_catalog', 'Invalid lesson list.')
        expected = {path, package/'source-map.json'}; seen = set(); all_pages = []
        if course.get('scenario_catalog'):
            if course['scenario_catalog'] != 'scenarios.json':
                raise XocError('academy_catalog','Unexpected scenario catalog path.')
            public_path=within(package,'scenarios.json');expected.add(public_path)
            from .livefire_content import public_catalog
            if json_document(read_bytes(public_path)) != public_catalog(root):
                raise XocError('academy_catalog','Run scripts/sync-livefire-catalog.py after editing scenarios.')
        source = json_document(read_bytes(within(package,'source-map.json')))
        last = course.get('public_pages')
        if type(last) is not int or source.get('approved_slide_range') != [1,last] or not 1 <= last <= 2000:
            raise XocError('academy_boundary', 'An explicit approved page boundary is required.')
        if cid == 'wazuh-threat-hunting' and last != 339:
            raise XocError('academy_boundary', 'This bundle is approved only through page 339.')
        for lesson in course['lessons']:
            lid = lesson['id']
            if not re.fullmatch(r'[a-z][a-z0-9-]{0,63}',lid) or lid in seen:
                raise XocError('academy_catalog', 'Lesson IDs must be unique and stable.')
            seen.add(lid)
            documents = {}
            for filename in ('lesson.json','explanation.json','missions.json'):
                file = within(package, 'lessons/'+lid+'/'+filename); expected.add(file)
                documents[filename] = json_document(read_bytes(file))
            pages = [s['page'] for s in documents['lesson.json']['slides']]
            if not pages or pages != list(range(lesson['source_pages'][0],lesson['source_pages'][1]+1)) or any(type(n) is not int or not 1 <= n <= last for n in pages):
                raise XocError('academy_boundary', 'Slide pages exceed the approved scope or have gaps.')
            all_pages.extend(pages)
            missions = documents['missions.json']
            if len(missions) != lesson['missions'] or len({m['id'] for m in missions}) != len(missions):
                raise XocError('academy_catalog', 'Mission identities must be unique.')
            for mission in missions:
                if not re.fullmatch(r'[a-z][a-z0-9-]{0,95}',mission['id']) or not set(mission['source_pages']) <= set(pages):
                    raise XocError('academy_catalog', 'Invalid mission source mapping.')
                if mission.get('response_field') not in (None,'input','output','interpretation'):
                    raise XocError('academy_catalog','Unknown mission input field.')
            for slide in documents['lesson.json']['slides']:
                for block in slide['blocks']:
                    if block['type']=='image' and block['asset'] not in course['assets']:
                        raise XocError('academy_asset', 'Every screenshot must be declared.')
        if sorted(all_pages) != list(range(1,last+1)):
            raise XocError('academy_boundary', 'Each approved slide must occur exactly once.')
        for name, info in course['assets'].items():
            if not re.fullmatch(r'[a-f0-9]{64}\.png',name): raise XocError('academy_asset','Invalid screenshot filename.')
            file = within(package, 'assets/'+name); expected.add(file)
            if file.stat().st_size > 8*1024**2:
                raise XocError('academy_asset','Screenshot exceeds 8 MiB.')
            raw = file.read_bytes()
            if len(raw) != info['bytes'] or hashlib.sha256(raw).hexdigest() != info['sha256'] or not raw.startswith(b'\x89PNG\r\n\x1a\n') or not info['source_pages'] or any(not 1<=n<=last for n in info['source_pages']):
                raise XocError('academy_asset','Screenshot hash or source boundary differs.')
        actual = {p for p in package.rglob('*') if p.is_file()}
        if any(p.is_symlink() for p in package.rglob('*')) or actual != expected:
            raise XocError('academy_undeclared','Content package contains undeclared files.')
        if sum(p.stat().st_size for p in expected)>128*1024**2:
            raise XocError('academy_size','Course package exceeds 128 MiB.')
        files.extend(sorted(expected)); courses.append(course)
    if not courses: raise XocError('academy_missing','The selected reader has no content packages.')
    return courses, files
