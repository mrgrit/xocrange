import json
from pathlib import Path
import shutil
import pytest
import yaml
from xocrange.livefire_content import scenarios,public_catalog
from xocrange.errors import XocError

ROOT=Path(__file__).resolve().parents[1]

def test_livefire_covers_courses_and_has_three_part_report_and_scored_answers():
    rows=scenarios(ROOT)
    assert len(rows)==15
    assert len([s for s,_ in rows if s['category']=='xoc-web-defense'])==8
    assert len([s for s,_ in rows if s['category']=='xoc-host-defense'])==7
    assert sum(len(s['red_missions'])+len(s['blue_missions']) for s,_ in rows)==105
    assert sum(len(s['academy']['lessons']) for s,_ in rows)==36
    public=public_catalog(ROOT)
    assert public==json.loads((ROOT/'contents/academy/wazuh-threat-hunting/scenarios.json').read_text())
    text=json.dumps(public,ensure_ascii=False)
    for forbidden in ('reference_answer','acceptable_methods','evaluation_cases','채점자 기준 답안'):
        assert forbidden not in text

@pytest.mark.parametrize('mutation',['points','purple','pages','grader','target','sections','rubric','cases'])
def test_invalid_grading_or_mapping_fails_before_publication(tmp_path,mutation):
    shutil.copytree(ROOT/'contents/catalog',tmp_path/'contents/catalog')
    shutil.copytree(ROOT/'contents/battle-scenarios',tmp_path/'contents/battle-scenarios')
    dest=tmp_path/'contents/academy/wazuh-threat-hunting';dest.mkdir(parents=True)
    shutil.copy2(ROOT/'contents/academy/wazuh-threat-hunting/course.json',dest/'course.json')
    p=tmp_path/'contents/battle-scenarios/xoc-web-01.yaml';s=yaml.safe_load(p.read_text())
    if mutation=='points':s['red_missions'][0]['points']=99
    if mutation=='purple':s['blue_missions']=s['blue_missions'][:3]
    if mutation=='pages':s['academy']['source_pages'].append(340)
    if mutation=='grader':s['red_missions'][0]['verify']['semantic']['acceptable_methods']=['answer removed']
    if mutation=='target':s['red_missions'][0]['assess_target']='self'
    if mutation=='sections':s['red_missions'][0]['submission']['sections'].pop()
    if mutation=='rubric':s['red_missions'][0]['rubric'][0]['id']='unknown'
    if mutation=='cases':s['red_missions'][0]['evaluation_cases'][0]['submission']='unstructured'
    p.write_text(yaml.safe_dump(s,allow_unicode=True))
    with pytest.raises(XocError):scenarios(tmp_path)
