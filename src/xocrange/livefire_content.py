"""tw2-compatible authored scenarios and an answer-free Core preview."""
import hashlib
import json
from pathlib import Path
import re
import yaml
from .errors import XocError

REFERENCE = '324d91fb22fee2c76051d5e73b58aa7f82de3e4c'


def subjects(root):
    from .documents import json_document, read_bytes
    items=json_document(read_bytes(Path(root)/'contents/catalog/subjects.json'))
    if not isinstance(items,list) or not 1<=len(items)<=200:
        raise XocError('scenario_subjects','Invalid subject catalog.')
    seen=set()
    for item in items:
        if (set(item)!={'id','title','subtitle'} or not re.fullmatch(r'[a-z][a-z0-9-]{0,63}',item['id'])
                or item['id'] in seen or any(not isinstance(item[k],str) or not 1<=len(item[k])<=300 for k in ('title','subtitle'))):
            raise XocError('scenario_subjects','Invalid subject identity or title.')
        seen.add(item['id'])
    return items


def scenarios(root):
    root=Path(root)
    course=json.loads((root/'contents/academy/wazuh-threat-hunting/course.json').read_text())
    lessons={l['id']:l for l in course['lessons']}
    subject_ids={x['id'] for x in subjects(root)}
    result=[]; covered=[]; ids=set()
    for path in sorted((root/'contents/battle-scenarios').glob('xoc-*.yaml')):
        if path.is_symlink() or path.stat().st_size>256*1024:
            raise XocError('scenario_path','Scenario file is not a bounded regular file.')
        s=yaml.safe_load(path.read_text())
        def require(value, message):
            if not value:raise XocError('scenario_contract',path.name+': '+message)
        require(s['id']==path.stem and s['id'] not in ids,'unique slug required');ids.add(s['id'])
        require(s['category'] in subject_ids,'unknown subject')
        linked=s['academy']['lessons'];require(linked and set(linked)<=set(lessons),'unknown lesson')
        covered.extend(linked)
        pages=sorted({p for lid in linked for p in range(lessons[lid]['source_pages'][0],lessons[lid]['source_pages'][1]+1)})
        require(s['academy']['source_pages']==pages and max(pages)<=339,'page boundary differs')
        totals={'red':0,'blue':0,'purple':0}; mission_ids=set()
        for side in ('red','blue'):
            missions=s[side+'_missions']
            expected_roles=['red','red'] if side=='red' else ['blue','blue','blue','purple','purple']
            require([m['learning_role'] for m in missions]==expected_roles,'mission sequence differs')
            require([m['order'] for m in missions]==list(range(1,len(missions)+1)),'nonconsecutive order')
            for m in missions:
                role=m['learning_role'];require(role in totals and (role=='red')==(side=='red'),'role mapping')
                require(m['assess_target']==('opponent' if side=='red' else 'self'),'evidence target differs')
                require(m['id'] not in mission_ids,'duplicate mission');mission_ids.add(m['id'])
                require(m['submission']['fields']==1 and m['submission']['type']=='text','one text input required')
                require(m['points']>0 and sum(c['points'] for c in m['rubric'])==m['points'],'rubric points differ')
                require(len(m['reference_answer']['answer'])>=8 and len(m['reference_answer']['explanation'])>=20,'reference answer too short')
                sem=m['verify']['semantic']
                require(all(sem.get(k) for k in ('intent','success_criteria','acceptable_methods','negative_signs')),'semantic contract missing')
                require(m['reference_answer']['answer'] in '\n'.join(sem['acceptable_methods']),'reference answer does not reach tw2 grader')
                checks=m['verify']['checks'];require(bool(checks),'missing assessor context')
                require(all(c['type']=='wazuh_alert' and c['target']=='siem' and c['params'].get('pattern') for c in checks),'invalid context check')
                require('### 따라 하기' in m['instruction'] and '### 제출은 하나' in m['instruction'],'learner guidance missing')
                require({x['kind'] for x in m['evaluation_cases']} >= {'full','wrong','empty'},'evaluation cases missing')
                totals[role]+=m['points']
        require(totals=={'red':35,'blue':45,'purple':20},'role score differs')
        require(s['runtime_contract']['purple_runtime_side']=='blue','Purple would be dropped by tw2')
        require(s['runtime_contract']['reference_commit']==REFERENCE,'reference drift')
        tokens=set(re.findall(r'\{\{\s*([A-Z_]+)\s*\}\}',path.read_text()))
        require(tokens<={'TARGET_IP','WEB_ENTRY','ATTACKER_IP'},'unsupported tw2 placeholder')
        result.append((s,path))
    if len(result)!=15 or sorted(covered)!=sorted(lessons):
        raise XocError('scenario_coverage','Expected 15 scenarios covering all 36 lessons exactly once.')
    return result


def public_catalog(root):
    """Explicit projection: grading answers/rubrics are never served by Core."""
    items=[]
    for s,path in scenarios(root):
        missions=[]
        for m in s['red_missions']+s['blue_missions']:
            missions.append({k:m[k] for k in ('id','order','title','learning_role','points','instruction','hint','submission')})
        items.append({k:s[k] for k in ('id','category','title','description','difficulty','time_limit','briefing','academy')}|{
            'missions':missions,'total_points':100,'source_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
            'execution_available':False,'minimum_tier':'live-fire'})
    return {'schema_version':'xoc.livefire-preview/0.1.0','subjects':subjects(root),'scenarios':items}
