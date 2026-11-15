#!/usr/bin/env python3
"""Validate authoring data and emit a bounded, versioned runtime payload."""
import argparse,hashlib,json,re
from pathlib import Path
from scenario_contract import public_catalog,scenarios
ROOT=Path(__file__).resolve().parents[1]
PAYLOAD=('academy','battle-scenarios','catalog','guides')
def read(p):return json.loads(p.read_text())
def validate():
    rows=scenarios(ROOT)
    course=read(ROOT/'academy/wazuh-threat-hunting/course.json')
    package=ROOT/'academy'/course['id'];source=read(package/'source-map.json')
    assert course['public_pages']==339 and source['approved_slide_range']==[1,339]
    assert len(course['lessons'])==36 and sum(x['missions'] for x in course['lessons'])==96
    pages=[];expected={package/'course.json',package/'source-map.json',package/'scenarios.json'}
    for lesson in course['lessons']:
        documents={}
        for name in ('lesson.json','explanation.json','missions.json'):
            p=package/'lessons'/lesson['id']/name;expected.add(p);documents[name]=read(p)
        actual=[s['page'] for s in documents['lesson.json']['slides']]
        assert actual==list(range(lesson['source_pages'][0],lesson['source_pages'][1]+1));pages.extend(actual)
        assert len(documents['missions.json'])==lesson['missions']
        for slide in documents['lesson.json']['slides']:
            for block in slide['blocks']:
                if block['type']=='image':assert block['asset'] in course['assets']
    assert sorted(pages)==list(range(1,340))
    for name,info in course['assets'].items():
        assert re.fullmatch(r'[a-f0-9]{64}\.png',name)
        p=package/'assets'/name;expected.add(p);data=p.read_bytes()
        assert data.startswith(b'\x89PNG\r\n\x1a\n') and len(data)==info['bytes']<=8*1024**2
        assert hashlib.sha256(data).hexdigest()==info['sha256']
        assert info['source_pages'] and all(1<=n<=339 for n in info['source_pages'])
    assert {p for p in package.rglob('*') if p.is_file()}==expected
    assert read(package/'scenarios.json')==public_catalog(ROOT),'Run sync-preview after editing scenarios'
    items=read(ROOT/'catalog/academy.json')['items'];assert len(items)==23 and len({x['id'] for x in items})==23
    assert read(ROOT/'guides/core-introduction.json')['schema_version']=='xoc.content/0.1.0'
    for directory in PAYLOAD:
        for p in (ROOT/directory).rglob('*'):assert not p.is_symlink()
    return {'courses':1,'lessons':36,'practice_missions':96,'scenarios':len(rows),'livefire_missions':105,'catalog_titles':23}
def write_manifest():
    result=validate();files={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for d in PAYLOAD for p in sorted((ROOT/d).rglob('*')) if p.is_file()}
    data={'schema_version':'xoc.content-module/0.1.0','id':'community-academy','version':'0.4.0','contracts':{'academy':'xoc.academy/0.1.0','livefire_preview':'xoc.livefire-preview/0.1.0'},'public_pages':[1,339],'files':dict(sorted(files.items()))}
    p=ROOT/'module.json';p.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
    return result|{'files':len(files),'manifest_sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
p=argparse.ArgumentParser();p.add_argument('command',choices=['validate','sync-preview','manifest']);a=p.parse_args()
if a.command=='sync-preview':
    target=ROOT/'academy/wazuh-threat-hunting/scenarios.json';target.write_text(json.dumps(public_catalog(ROOT),ensure_ascii=False,indent=2)+'\n');result=validate()
else:result=write_manifest() if a.command=='manifest' else validate()
print(json.dumps(result))
