#!/usr/bin/env python3
"""Run C1 events through the real Wazuh engine with this tree's C1 decoder and rules.

An event Wazuh matches with no 110xxx rule is never confirmed, so the store's backlog grows and
installation acceptance fails. This check builds events with the collector's own adapters and asks
a disposable Wazuh (no network) which rule and level each one gets.
Usage (root, on a host that has the Manager image): c1_rules.py [--image IMAGE]
"""
import argparse, json, shutil, subprocess, sys, time
from pathlib import Path

IMAGE='wazuh/wazuh-manager@sha256:dcda4869e2f792e92f03bce93f85b4bdf103756ea61cfca8ba9f3eabeb05365b'
FACILITY={'schema_version':'xoc.facility-event/0.1.0','at':'2026-11-20T12:26:46Z','message':'경보: 항온항습기 정지 (항온항습기 A)'}


def cases(root):
    sys.path.insert(0,str(root/'src'))
    from xocrange.events import Context, normalize
    context=Context('community','range-01','fixture','ref-1','2026-11-20T12:27:00.000000Z')
    def one(source,record):
        event,=normalize(source,json.dumps(record).encode(),context)
        return json.dumps(event,ensure_ascii=False,separators=(',',':'))
    rows=[('facility-critical',one('xoc-facility',FACILITY|{'kind':'alarm','level':'critical','alarm':'crac_stopped.crac-01','asset_id':'crac-01'}),'110013',12),
          ('facility-warning',one('xoc-facility',FACILITY|{'kind':'alarm','level':'warning','alarm':'aisle_temp_high.A'}),'110012',7),
          ('facility-inject',one('xoc-facility',FACILITY|{'kind':'inject','fault':'crac_fail','target':'crac-01','requested_by':'student01','message':'장애 주입: 항온항습기 정지 (항온항습기 A), 3분'}),'110011',5),
          ('facility-recover',one('xoc-facility',FACILITY|{'kind':'recover','fault':'crac_fail','target':'crac-01','message':'장애 자동 복구: 항온항습기 정지 (항온항습기 A)'}),'110010',3),
          ('facility-cleared-alarm',one('xoc-facility',FACILITY|{'kind':'info','alarm':'aisle_temp_high.A','message':'경보 해제: 구역 온도 상승 (2F A열)'}),'110010',3),
          ('agent',one('xoc-agent',{'schema_version':'xoc.agent-activity/0.1.0','at':'2026-11-20T12:26:46Z','role':'operator','tool':'siem_search','decision':'allow'}),'110009',3)]
    return [dict(name=n,event='xoc-c1: '+e,rule=r,level=l) for n,e,r,l in rows]


def inside():
    root=Path('/var/ossec')
    for kind in ('permanent','exclusion'):
        source=root/'data_tmp'/kind/'var/ossec'
        if source.exists():shutil.copytree(source,root,dirs_exist_ok=True)
    for kind,name in (('decoders','c1-decoder.xml'),('rules','c1-rules.xml')):
        (root/'etc'/('test-'+kind)).mkdir(exist_ok=True)
        shutil.copyfile('/src/components/siem/'+name,root/'etc'/('test-'+kind)/name)
    (root/'etc/ossec.conf').write_text('''<ossec_config><global><jsonout_output>yes</jsonout_output></global>
      <ruleset><decoder_dir>etc/test-decoders</decoder_dir><decoder_dir>ruleset/decoders</decoder_dir>
      <rule_dir>ruleset/rules</rule_dir><rule_exclude>0215-policy_rules.xml</rule_exclude>
      <list>etc/lists/audit-keys</list><list>etc/lists/amazon/aws-eventnames</list><list>etc/lists/security-eventchannel</list>
      <list>etc/lists/malicious-ioc/malicious-ip</list><list>etc/lists/malicious-ioc/malicious-domains</list>
      <list>etc/lists/malicious-ioc/malware-hashes</list><rule_dir>etc/test-rules</rule_dir></ruleset></ossec_config>''')
    for relative in ('etc','queue','logs','var'):
        parent=root/relative;parent.mkdir(exist_ok=True)
        for path in (parent,*parent.rglob('*')):shutil.chown(path,user='wazuh',group='wazuh')
    for relative in ('queue/fts','queue/diff','logs'):
        path=root/relative;path.mkdir(exist_ok=True);path.chmod(0o770)
    log=open('/tmp/engine.log','w');processes=[]
    try:
        for name in ('wazuh-db','wazuh-analysisd'):
            processes.append(subprocess.Popen([str(root/'bin'/name),'-f'],stdout=log,stderr=log))
        for _ in range(200):
            if (root/'queue/sockets/logtest').exists():break
            time.sleep(.1)
        else:raise RuntimeError(Path('/tmp/engine.log').read_text()[-5000:])
        sys.path.insert(0,str(root/'framework/scripts'))
        from wazuh_logtest import WazuhLogtest
        results=[]
        for case in json.load(sys.stdin):
            client=WazuhLogtest(location='xoc-c1')
            try:result=client.process_log(case['event'])['output']
            finally:client.remove_last_session()
            rule=result.get('rule',{})
            results.append(dict(name=case['name'],passed=str(rule.get('id'))==case['rule'] and rule.get('level')==case['level']
                and result.get('decoder',{}).get('name')=='xoc-c1',rule=rule.get('id'),level=rule.get('level'),
                description=rule.get('description'),decoder=result.get('decoder',{}).get('name')))
        print(json.dumps(results,ensure_ascii=False))
    finally:
        for proc in processes:proc.terminate()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside',action='store_true');parser.add_argument('--image',default=IMAGE)
    args=parser.parse_args()
    if args.inside:return inside()
    root=Path(__file__).resolve().parents[2]
    result=subprocess.run(['docker','run','--rm','-i','--network','none','--memory','2g','--pids-limit','128',
        '--mount',f'type=bind,src={root},dst=/src,readonly','--entrypoint','/var/ossec/framework/python/bin/python3',args.image,
        '/src/tests/integration/c1_rules.py','--inside'],input=json.dumps(cases(root)),text=True,capture_output=True)
    if result.returncode:raise RuntimeError(result.stderr[-6000:]+result.stdout[-1000:])
    rows=json.loads(result.stdout);failed=[row for row in rows if not row['passed']]
    print(json.dumps({'passed':not failed,'cases':len(rows),'failed':failed,'rows':rows},ensure_ascii=False,indent=1))
    return bool(failed)


if __name__=='__main__':raise SystemExit(main())
