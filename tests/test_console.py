"""Policy boundaries and revision/restore behavior without touching a host firewall."""
import json
from pathlib import Path
import sys
import pytest
from xocrange.planner import plan

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'components/security-path/runtime/console'))
from engine import candidate,compile_policy,empty
from broker import Device,Conflict


def change(**fields):
    return {'operation':'upsert','kind':'rule','name':'Test policy','fields':fields}


@pytest.mark.parametrize('device,fields',[
 ('fw',{'saddr':'1.2.3.4\nflush ruleset','action':'drop'}),
 ('fw',{'saddr':'1.2.3.4;flush ruleset'}),('fw',{'chain':'input'}),
 ('fw',{'proto':'tcp','dport':'65536'}),('fw',{'proto':'icmp','dport':'80'}),
 ('fw',{'iif':'eth0" drop'}),('fw',{'log':'false'}),
 ('ips',{'content':'x"; sid:1;'}),('ips',{'content':'x\nalert ip any any -> any any'}),
 ('ips',{'proto':'http','dport':'8443'}),('ips',{'proto':'ip'}),
 ('waf',{'pattern':'foo\nSecRuleEngine Off'}),('waf',{'pattern':'foo','status':'403,ctl:ruleEngine=Off'}),
 ('waf',{'variable':'REQUEST_URI|&ARGS','pattern':'foo'}),
])
def test_policy_fields_cannot_escape_reviewed_scope(device,fields):
    with pytest.raises((ValueError,KeyError)):
        compile_policy(device,candidate(device,empty(),change(**fields)))


def test_fw_forward_scope_preserves_management_and_both_ports():
    s=candidate('fw',empty(),change(proto='tcp',sport='1024-65535',dport='80,443',action='drop',log=True))
    text=compile_policy('fw',s)
    assert 'chain forward' in text and 'chain input' not in text and 'flush ruleset' not in text
    assert 'tcp sport 1024-65535' in text and 'tcp dport { 80, 443 }' in text
    assert text.index('tcp dport 8443 return')<text.index('dport { 80, 443 }')
    assert 'group 10' in text and 'delete table inet xoc_policy' in text
    assert 'delete table inet xoc_fw' not in text


def test_object_ports_and_policy_move_keep_stable_id():
    s=candidate('fw',empty(),{'operation':'upsert','kind':'object','name':'Web ports','fields':{'name':'web_ports','type':'inet_service','elements':'80,443'}})
    s=candidate('fw',s,change(proto='tcp',dport='@web_ports',action='accept'))
    first=s['rules'][0]['id'];s=candidate('fw',s,change(action='drop'))
    s=candidate('fw',s,{'operation':'move','kind':'rule','id':first,'position':1})
    assert s['rules'][1]['id']==first
    assert 'dport @web_ports' in compile_policy('fw',s)


def test_ips_management_exclusion_and_waf_only_generated_rule():
    s=candidate('ips',empty(),change(proto='http',content='test',action='drop'))
    assert '[0:8442,8444:65535]' in compile_policy('ips',s)
    s=candidate('waf',empty(),change(variable='REQUEST_URI',operator='@contains',pattern='test',action='deny'))
    text=compile_policy('waf',s)
    assert 'id:9000001' in text and 'status:403' in text and 'ctl:' not in text


class FakeDevice(Device):
    def validate(self,text):
        if 'INVALID' in text: raise ValueError('syntax failure')
    def activate(self,text):
        self.applied=text
        if getattr(self,'fail_once',False):
            self.fail_once=False;raise ValueError('reload failed')


def preview(d,actor='admin'):
    return d.request({'action':'preview','version':d.state()['version'],'actor':actor,'payload':change(proto='tcp',dport='8080',action='drop')})


def apply(d,p,actor='admin'):
    return d.request({'action':'apply','version':p['version'],'actor':actor,'token':p['token'],'request_id':'a'*32})


def test_preview_does_not_apply_and_ticket_bound_to_actor_revision(tmp_path):
    d=FakeDevice('fw',tmp_path);p=preview(d)
    assert d.state()['version']==0 and not hasattr(d,'applied')
    with pytest.raises(Conflict):apply(d,p,'operator')
    assert apply(d,p)['version']==1
    with pytest.raises(Conflict):apply(d,p)
    assert d.state()['rules'] and len(d.state()['history'])==1


def test_new_preview_supersedes_old_and_failed_reload_restores(tmp_path):
    d=FakeDevice('fw',tmp_path);old=preview(d);new=preview(d)
    with pytest.raises(Conflict):apply(d,old)
    d.fail_once=True
    with pytest.raises(ValueError,match='reload failed'):apply(d,new)
    assert d.state()==empty() and d.applied==compile_policy('fw',empty())
    assert 'restored' in (tmp_path/'operations.jsonl').read_text()


def test_restore_creates_new_revision_and_policy_survives_reopen(tmp_path):
    d=FakeDevice('fw',tmp_path);apply(d,preview(d));d=FakeDevice('fw',tmp_path)
    assert d.state()['version']==1
    p=d.request({'action':'preview','version':1,'actor':'admin','payload':{'operation':'rollback'}})
    assert apply(d,p)['version']==2
    assert d.state()['rules']==[] and len(d.state()['history'])==2


def test_expired_preview_is_rejected(tmp_path):
    d=FakeDevice('fw',tmp_path);p=preview(d);ticket=json.loads((tmp_path/'ticket.json').read_text());ticket['expires']=0;(tmp_path/'ticket.json').write_text(json.dumps(ticket))
    with pytest.raises(Conflict):apply(d,p)


def test_console_selection_adds_only_device_socket_without_new_privileges():
    p=plan(ROOT,preset='security-path',include=['console-fw'],allow_experimental=True)
    services=p['compose']['services'];assert services['fw']['environment']['XOC_CONSOLE']=='1'
    assert 'XOC_CONSOLE' not in services['ips']['environment']
    assert services['fw']['cap_add']==['NET_ADMIN'] and 'ports' not in services['fw']
    assert 'console-fw-socket:/run/xoc-console-fw:ro' in services['platform']['volumes']
    q=plan(ROOT,preset='security-path',include=['management'],allow_experimental=True)
    assert 'console-fw-state:/var/lib/xoc-console' in q['compose']['services']['fw']['volumes']
    assert 'XOC_CONSOLE' not in q['compose']['services']['fw']['environment']


def test_rule_ids_are_not_reused_after_delete():
    s=candidate('ips',empty(),change(proto='http',content='first'))
    original=s['rules'][0]
    s=candidate('ips',s,{'operation':'delete','id':original['id']})
    s=candidate('ips',s,change(proto='http',content='second'))
    assert s['rules'][0]['rule_id']>original['rule_id']


def test_suricata_literal_semicolon_is_encoded_and_old_history_ids_reserved():
    s=candidate('ips',empty(),change(proto='http',content='; cat /etc/passwd'))
    assert 'content:"|3B| cat /etc/passwd"' in compile_policy('ips',s)
    old=empty();old.pop('next_rule_id');old['history']=[{'previous':{'rules':[s['rules'][0]],'objects':[],'nat':[]}}]
    updated=candidate('ips',old,change(proto='http',content='next'))
    assert updated['rules'][0]['rule_id']>s['rules'][0]['rule_id']
