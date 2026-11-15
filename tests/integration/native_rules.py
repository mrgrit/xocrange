#!/usr/bin/env python3
"""Compare actual Wazuh engines in disposable, network-isolated containers.

The legacy rule file is a read-only review input, never installed on the host.
Run with the project's Python and Docker on the dedicated validation VM.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

OLD='wazuh/wazuh-manager@sha256:77fc060a380dd995b541fd525034f4f8f58c6efa7a625b15f4c9251f0353a69c'
NEW='wazuh/wazuh-manager@sha256:dcda4869e2f792e92f03bce93f85b4bdf103756ea61cfca8ba9f3eabeb05365b'


def cases(root, legacy=False):
    from xocrange.native_input import frames
    fixtures=root/'tests/fixtures/events'
    output=[]
    def add(name,source,raw,rule,decoder,fields=None,old_rule=None,old_decoder=None,location=None):
        text=raw.decode() if isinstance(raw,bytes) else raw
        if legacy:
            # kt66 used standard osquery wrapping and raw audit/XML/common logs.
            if source=='auditd':text=' '.join(text.splitlines())
            if source=='osquery':text=json.dumps({'osquery':json.loads(text)})
            if source in ('suricata','modsecurity'):text=json.dumps(json.loads(text),separators=(',',':'))
        else:text=frames(source,text.encode())[0]
        output.append(dict(name=name,event=text,source=source,
            location=location or ('/var/log/apache2/modsec_audit.log' if legacy and source=='modsecurity' else
                'xoc-native/'+'a'*64+'/'+source),
            rule=old_rule if legacy and old_rule is not None else rule,
            decoder=old_decoder if legacy and old_decoder is not None else decoder,
            fields={} if legacy and old_decoder=='' else fields or {}))
    add('nft-core-iso','nftables',(fixtures/'nftables-drop.log').read_bytes(),'4101','xoc-nftables',
        {'srcip':'192.0.2.10','action':'DROP'},old_rule='',old_decoder='')
    add('nft-core-nflog','nftables','2026-11-07T13:00:00Z fw kernel: [xoc-fw] DROP IN=netns OUT=netns SRC=192.0.2.10 DST=198.51.100.20 PROTO=TCP SPT=51000 DPT=443','4101','xoc-nftables',
        {'srcip':'192.0.2.10','dstport':'443','action':'DROP'},old_rule='',old_decoder='')
    for action,rule in [('DROP','4101'),('ACCEPT','4100')]:
        add('nft-fractional-'+action.lower(),'nftables',f'2026-11-07T13:00:00.404931Z fw kernel: [xoc-fw] {action} IN=netns OUT=netns SRC=192.0.2.10 DST=198.51.100.20 PROTO=TCP SPT=51000 DPT=443',rule,'xoc-nftables',
            {'srcip':'192.0.2.10','dstport':'443','action':action},old_rule='',old_decoder='')
    add('suricata-alert','suricata',(fixtures/'suricata-alert.json').read_bytes(),'86601','json',{'event_type':'alert','alert.signature_id':'1000001','alert.action':'blocked'})
    add('osquery-query','osquery',(fixtures/'osquery-results.json').read_bytes(),'24010','json',{'osquery.name':'core_processes','osquery.columns.pid':'42'})
    add('sysmon-linux-process','sysmon',(fixtures/'sysmon-process.xml').read_bytes(),'111201','json',
        {'sysmon_linux.provider':'Linux-Sysmon','sysmon_linux.event_id':'1'},old_rule='',old_decoder='')
    for event_id,rule in [(3,'111203'),(11,'111211')]:
        xml=(fixtures/'sysmon-process.xml').read_text().replace('<EventID>1</EventID>',f'<EventID>{event_id}</EventID>')
        add('sysmon-linux-'+str(event_id),'sysmon',xml,rule,'json',
            {'sysmon_linux.provider':'Linux-Sysmon','sysmon_linux.event_id':str(event_id)},old_rule='',old_decoder='')
    audit=(fixtures/'auditd-exec.log').read_text()
    add('audit-group','auditd',audit,'80700','auditd',{'audit.key':'xoc_probe'})
    add('audit-abort','auditd','type=DAEMON_ABORT msg=audit(1794056400.123:100): op=terminate auid=1000 pid=42 res=failed','80704','auditd')
    for status,rule in ((200,'31108'),(403,'31101'),(500,'31122')):
        add('apache-'+str(status),'apache-access',f'192.0.2.10 - - [07/Nov/2026:13:00:00 +0000] "GET / HTTP/1.1" {status} 42 xoc_id=fixture',''+rule,'web-accesslog')
    add('apache-sqli','apache-access','192.0.2.10 - - [07/Nov/2026:13:00:00 +0000] "GET /?q=select%20password%20from%20users HTTP/1.1" 403 42','31103','web-accesslog')
    add('apache-empty-timeout','apache-access','192.0.2.10 - - [07/Nov/2026:13:00:00 +0000] "-" 408 0 xoc_id=-','31100','xoc-apache-empty-request',{'http_status':'408','response_bytes':'0'},old_rule='',old_decoder='')
    ua='192.0.2.10 - - [15/Nov/2026:13:00:00 +0000] "GET {} HTTP/1.1" {} 42 "-" "{}" xoc_id=fixture'
    for name,url,status,agent,rule in [('ua-browser','/',200,'curl/8.5.0','31108'),('ua-browser-404','/x',404,'Mozilla/5.0 \\"q\\"','31101'),
            ('ua-sqlmap','/index.php?id=1',200,'sqlmap/1.8.4#stable (https://sqlmap.org)','111303'),
            ('ua-nikto-500','/',500,'Mozilla/5.00 (Nikto/2.5.0)','111303'),('ua-gobuster-404','/admin',404,'gobuster/3.6','111303'),
            ('ua-sqli-keeps-31103','/?q=select%20password%20from%20users',403,'sqlmap/1.8.4','31103')]:
        add(name,'apache-access',ua.format(url,status,agent),rule,'web-accesslog',old_rule='',old_decoder='')
    add('apache-empty-ua','apache-access','192.0.2.10 - - [15/Nov/2026:13:00:00 +0000] "-" 408 0 "-" "-" xoc_id=-','31100','xoc-apache-empty-request',{'http_status':'408','response_bytes':'0'},old_rule='',old_decoder='')
    add('apache-error','apache-error',(fixtures/'apache-error.log').read_bytes(),'30315','apache-errorlog')
    base=json.loads((fixtures/'modsecurity-audit.json').read_bytes())
    variants=[('normal',[],200,'ENABLED','119670',None),
        ('warning',['Warning. [id "920350"]'],200,'ENABLED','119671',None),
        ('block',['Access denied with code 403 (phase 2). [id "949110"]'],403,'ENABLED','119672',None),
        ('ahz-block',['Warning.', 'Access denied with code 403 (phase 2). [id "949110"]'],None,'ENABLED','119672','119671'),
        ('application-403',['Warning. [id "920350"]'],403,'ENABLED','119671',None),
        ('embedded-denial',['Warning. [data "Access denied with code 403 (phase 2)."]'],403,'ENABLED','119671','119672'),
        ('detection-only',['Access denied with code 403 (phase 2). [id "949110"]'],403,'DETECTION_ONLY','119671','119672'),
        ('body-only',[],403,'ENABLED','119670',None)]
    for name,messages,status,mode,rule,old_rule in variants:
        value=json.loads(json.dumps(base));value['response']={'body':'Access denied with code 403 (phase 2).'}
        if status is not None:value['response']['status']=status
        value['audit_data'].update(messages=messages,engine_mode=mode)
        value['xoc_modsecurity']={'intervention':True}  # must be recomputed
        add('waf-'+name,'modsecurity',json.dumps(value),rule,'json',old_rule=old_rule)
    # The same structured input at an unrelated location cannot claim WAF IDs.
    add('waf-wrong-source','modsecurity',json.dumps(base),'!119670,119671,119672','json',location='unrelated.log')
    return output


def inside(mode):
    root=Path('/var/ossec')
    for kind in ('permanent','exclusion'):
        source=root/'data_tmp'/kind/'var/ossec'
        if source.exists():shutil.copytree(source,root,dirs_exist_ok=True)
    for kind in ('decoders','rules'):(root/'etc'/('test-'+kind)).mkdir(exist_ok=True)
    if mode=='legacy':shutil.copyfile('/legacy.xml',root/'etc/test-rules/legacy.xml')
    else:
        for kind in ('decoders','rules'):
            shutil.copyfile('/src/components/siem/native-'+kind+'.xml',root/'etc'/('test-'+kind)/'native.xml')
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
    log=open('/tmp/engine.log','w')
    processes=[]
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
            client=WazuhLogtest(location=case['location'])
            try:result=client.process_log(case['event'])['output']
            finally:client.remove_last_session()
            rule=result.get('rule',{});decoder=result.get('decoder',{}).get('name','')
            identifier=str(rule.get('id',''))
            matched=identifier not in case['rule'][1:].split(',') if case['rule'].startswith('!') else identifier==case['rule']
            def get_field(data,key):
                for part in key.split('.'):data=data.get(part,{}) if isinstance(data,dict) else None
                return str(data)
            fields=all(get_field(result.get('data',{}),k)==str(v) for k,v in case['fields'].items())
            levels={'4100':0,'4101':5,'86601':3,'24010':3,'111201':3,'111203':3,'111211':3,'31100':0,'80700':0,'80704':10,'31108':0,'31101':5,'31122':5,'31103':7,'111303':6,'30315':5,'119670':3,'119671':5,'119672':7,'':None}
            level_matches=case['rule'].startswith('!') or rule.get('level')==levels[case['rule']]
            results.append(dict(name=case['name'],passed=matched and decoder==case['decoder'] and fields and level_matches,
                expected_rule=case['rule'],rule=identifier,level=rule.get('level'),decoder=decoder,
                fields=result.get('data',{}),static_fields={k:result[k] for k in ('srcip','dstip','action') if k in result}))
        print(json.dumps(results))
    finally:
        for proc in processes:proc.terminate()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside',choices=['legacy','candidate'])
    parser.add_argument('--legacy-rules',type=Path)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    if args.inside:return inside(args.inside)
    if not args.legacy_rules or not args.output:parser.error('--legacy-rules and --output are required')
    root=Path(__file__).resolve().parents[2];report={}
    for mode,image in [('legacy',OLD),('candidate',NEW)]:
        result=subprocess.run(['docker','run','--rm','-i','--network','none','--memory','2g','--pids-limit','128',
            '--mount',f'type=bind,src={root},dst=/src,readonly',
            '--mount',f'type=bind,src={args.legacy_rules.resolve()},dst=/legacy.xml,readonly',
            '--entrypoint','/var/ossec/framework/python/bin/python3',image,
            '/src/tests/integration/native_rules.py','--inside',mode],
            input=json.dumps(cases(root,mode=='legacy')),text=True,capture_output=True)
        if result.returncode:raise RuntimeError(result.stderr[-6000:]+result.stdout[-1000:])
        report[mode]={'image':image,'cases':json.loads(result.stdout)}
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    failed=[mode+':'+row['name'] for mode,item in report.items() for row in item['cases'] if not row['passed']]
    print(json.dumps({'passed':not failed,'cases':sum(len(v['cases']) for v in report.values()),'failed':failed}))
    return bool(failed)


if __name__=='__main__':raise SystemExit(main())
