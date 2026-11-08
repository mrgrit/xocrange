"""Bounded plain-text Community bundle; no HTML, scripts, scores or user progress."""
from .documents import json_document, read_bytes
from .errors import XocError


def bundle(root):
    data = json_document(read_bytes(root/'contents/guides/core-introduction.json'))
    if set(data) != {'schema_version','id','version','title','articles'} or data['schema_version'] != 'xoc.content/0.1.0':
        raise XocError('invalid_content', 'Unsupported content bundle')
    if not isinstance(data['articles'], list) or not 1 <= len(data['articles']) <= 32:
        raise XocError('invalid_content', 'Expected 1–32 articles')
    import re
    seen = set()
    for item in data['articles']:
        if set(item) != {'id','title','summary','minutes','requires','related_panels','sections'}:
            raise XocError('invalid_content', 'Unsupported article fields')
        if not re.fullmatch('[a-z][a-z0-9-]{0,63}', item['id']) or item['id'] in seen:
            raise XocError('invalid_content', 'Article IDs must be unique')
        seen.add(item['id'])
        if type(item['minutes']) is not int or not 1 <= item['minutes'] <= 120:
            raise XocError('invalid_content', 'Invalid reading estimate')
        for key in ('title','summary'):
            if not isinstance(item[key], str) or not 1 <= len(item[key]) <= 300:
                raise XocError('invalid_content', 'Invalid article text')
        for key in ('requires','related_panels'):
            if not isinstance(item[key], list) or any(not isinstance(v,str) or not re.fullmatch('[a-z][a-z0-9-]{0,63}',v) for v in item[key]):
                raise XocError('invalid_content', 'Invalid article reference')
        if not isinstance(item['sections'], list) or not 1 <= len(item['sections']) <= 16:
            raise XocError('invalid_content', 'Invalid article sections')
        for section in item['sections']:
            if set(section) != {'title','paragraphs'} or not isinstance(section['title'],str) or not 1 <= len(section['title']) <= 120:
                raise XocError('invalid_content', 'Invalid section heading')
            if not isinstance(section['paragraphs'],list) or not 1 <= len(section['paragraphs']) <= 16 or any(not isinstance(p,str) or not 1 <= len(p) <= 2000 for p in section['paragraphs']):
                raise XocError('invalid_content', 'Invalid section text')
    return data
