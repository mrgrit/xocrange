#!/usr/bin/env python3
"""Run the reference engine's pure content functions without starting its DB/LLM."""
import argparse
import ast
from dataclasses import dataclass,field
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from typing import Any

root=Path(__file__).resolve().parents[1];sys.path.insert(0,str(root/'src'))
from xocrange.livefire_content import scenarios,REFERENCE

p=argparse.ArgumentParser();p.add_argument('--tw2',required=True,type=Path);p.add_argument('--output',type=Path)
a=p.parse_args();ref=a.tw2.resolve()
head=subprocess.check_output(['git','-C',str(ref),'rev-parse','HEAD'],text=True).strip()
if head!=REFERENCE:raise SystemExit('Reference checkout differs from the reviewed engine commit.')

def definitions(path,names,namespace):
    tree=ast.parse((ref/path).read_text())
    body=[ast.ImportFrom(module='__future__',names=[ast.alias(name='annotations')],level=0)]
    body.extend(n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in names or isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id in names for t in n.targets))
    exec(compile(ast.fix_missing_locations(ast.Module(body=body,type_ignores=[])),str(ref/path),'exec'),namespace)

loader={'Any':Any};definitions('apps/api/app/services/scenario_loader.py',{'_summary','_normalize'},loader)
spec=importlib.util.spec_from_file_location('reference_check_compiler',ref/'apps/api/app/services/check_compiler.py')
compiler=importlib.util.module_from_spec(spec);spec.loader.exec_module(compiler)
validator={'compile_mission_checks':compiler.compile_mission_checks,'ASSESSOR_TYPES':compiler.ASSESSOR_TYPES}
definitions('scripts/validate_scenarios.py',{'check_mission','REQUIRED_PARAMS','VALID_TARGETS','LOG_ALIASES'},validator)
contexts={'dataclass':dataclass,'field':field}
definitions('apps/api/app/services/event_analyzer.py',{'MissionContext'},contexts)
router={'ea':SimpleNamespace(MissionContext=contexts['MissionContext'])}
definitions('apps/api/app/routers/battles.py',{'_build_mission_context'},router)
checks={};count=0;purple=0
for s,_ in scenarios(root):
    norm=loader['_normalize'](s,s['id']);obj=SimpleNamespace(**norm)
    assert norm['scoring']['red']['total_points']==35 and norm['scoring']['blue']['total_points']==65
    assert sum(m['learning_role']=='purple' for m in norm['mission_blue']['missions'])==2
    for side in ('red','blue'):
        for m in s[side+'_missions']:
            errors=[];warnings=[];validator['check_mission'](side,m,errors,warnings)
            assert not errors and not warnings,(s['id'],m['id'],errors,warnings)
            ctx=router['_build_mission_context'](obj,side,m['order'])
            assert m['reference_answer']['answer'] in '\n'.join(ctx.acceptable_methods)
            assert ctx.points==sum(c['points'] for c in m['rubric'])
            count+=1;purple+=m['learning_role']=='purple'
    checks[s['id']]=True
result={'status':'passed','reference_commit':head,'scenarios':len(checks),'missions':count,'purple_missions_preserved':purple,
        'checks':checks,'verification':['reference _normalize','reference check compiler and validator','reference mission-to-grader context; answers and rubric reach semantic grading'],
        'scope':'Static content/engine contract only. No AI inference, Assessor connection, live attack, or runtime import was performed.'}
if a.output:a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
