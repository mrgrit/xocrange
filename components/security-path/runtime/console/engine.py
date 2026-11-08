"""Typed device policy compiler. Canonical generators are pure, never shell executors."""
import copy
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import time
import uuid
import fw_builders
import ips_builders
import waf_builders

FIELDS = {
 'fw': {'saddr','daddr','proto','sport','dport','iif','oif','ct_state','limit_rate','limit_over','log','action'},
 'ips': {'action','proto','src','sport','dst','dport','dir','msg','flow','buffer','content','content_negate','nocase','pcre','threshold_count','threshold_seconds','threshold_track','threshold_type','classtype'},
 'waf': {'variable','operator','pattern','phase','action','severity','transforms','msg','status'},
 'object': {'name','type','elements'},
 'nat': {'kind','iif','oif','proto','dport','to_ip','to_port','saddr'},
}


def run(argv, *, text=None, timeout=20):
    proc = subprocess.run(argv, input=text, text=True, capture_output=True, timeout=timeout)
    if proc.returncode:
        raise ValueError((proc.stderr or proc.stdout or 'Device command failed')[-2000:])
    return proc.stdout


def empty():
    return {'version': 0, 'rules': [], 'objects': [], 'nat': [], 'history': [], 'next_rule_id':9000001}


def safe_text(value):
    if isinstance(value, str) and (len(value) > 300 or any(ord(c) < 32 for c in value)):
        raise ValueError('Invalid field length or control character')
    if isinstance(value, list):
        if len(value) > 8: raise ValueError('Too many values')
        for item in value: safe_text(item)
    elif not isinstance(value, (str, bool, int)):
        raise ValueError('Invalid field type')


def address(value, *, group=True):
    if not value or value == 'any': return ''
    if group and re.fullmatch(r'@[A-Za-z_][A-Za-z0-9_]{0,31}', value): return value
    items = [x.strip() for x in value.strip('{} ').split(',')]
    for item in items:
        net = ipaddress.ip_network(item, strict=False)
        if net.version != 4: raise ValueError('This profile supports IPv4 addresses')
    return items[0] if len(items) == 1 else '{ '+', '.join(items)+' }'


def port(value, *, group=False):
    if not value or value == 'any': return ''
    if group and re.fullmatch(r'@[A-Za-z_][A-Za-z0-9_]{0,31}', value): return value
    items = [x.strip() for x in str(value).strip('{} ').split(',')]
    for item in items:
        if not re.fullmatch(r'\d{1,5}(?:-\d{1,5})?', item): raise ValueError('Invalid port')
        nums = [int(n) for n in item.split('-')]
        if not all(1 <= n <= 65535 for n in nums) or nums[0] > nums[-1]: raise ValueError('Invalid port range')
    return items[0] if len(items) == 1 else '{ '+', '.join(items)+' }'


def validate_fields(device, kind, fields):
    if kind not in ('rule','object','nat') or (device != 'fw' and kind != 'rule'): raise ValueError('Unsupported policy kind')
    schema = device if kind == 'rule' else kind
    if not isinstance(fields, dict) or fields.keys() - FIELDS[schema]: raise ValueError('Unknown policy field')
    for value in fields.values(): safe_text(value)
    f = copy.deepcopy(fields)
    for key in ('log','limit_over','nocase','content_negate'):
        if key in f and type(f[key]) is not bool: raise ValueError('Expected a checkbox value')
    if schema == 'fw':
        for k in ('saddr','daddr'): f[k] = address(f.get(k,''))
        for k in ('sport','dport'): f[k] = port(f.get(k,''), group=True)
        if f.get('proto','') not in ('','tcp','udp','icmp'): raise ValueError('Invalid protocol')
        if (f['sport'] or f['dport']) and f.get('proto') not in ('tcp','udp'): raise ValueError('Ports require TCP or UDP')
        if f.get('ct_state','') not in ('','new','established,related'): raise ValueError('Invalid connection state')
        for k in ('iif','oif'):
            if f.get(k) and not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}',f[k]): raise ValueError('Invalid interface')
        if f.get('limit_rate') and not re.fullmatch(r'[1-9][0-9]{0,6}/(?:second|minute|hour|day)',f['limit_rate']): raise ValueError('Invalid rate')
    elif schema == 'object':
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,31}', f.get('name','')): raise ValueError('Invalid object name')
        if f.get('type') not in ('ipv4_addr','inet_service'): raise ValueError('Invalid object type')
        values = [v for v in re.split(r'[,\s]+',f.get('elements','')) if v]
        if not values or len(values)>64: raise ValueError('Expected 1–64 object members')
        for v in values: address(v,group=False) if f['type']=='ipv4_addr' else port(v)
        f['elements']=', '.join(values)
    elif schema == 'nat':
        for k in ('to_ip','saddr'):
            if f.get(k): f[k]=address(f[k],group=False)
        for k in ('to_port','dport'):
            if f.get(k): f[k]=port(f[k])
        for k in ('iif','oif'):
            if f.get(k) and not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}',f[k]): raise ValueError('Invalid interface')
    elif schema == 'ips':
        if f.get('proto','http') not in ('http','tcp','udp','dns','tls','icmp','ip'): raise ValueError('Invalid protocol')
        # Suricata syntax has quoting rules distinct from shell syntax.
        for k in ('msg','content','pcre'):
            if any(c in f.get(k,'') for c in ('"','\\')): raise ValueError('Quotes/backslashes are not supported in this form')
        if f.get('buffer') and f['buffer'] not in ips_builders.HTTP_BUFFERS: raise ValueError('Invalid inspection buffer')
        for k in ('src','dst'):
            v=f.get(k,'any') or 'any'
            if v not in ('any','$HOME_NET','$EXTERNAL_NET'): address(v,group=False)
        for k in ('sport','dport'):
            v=f.get(k,'any') or 'any'
            if v!='any':
                port(v)
                if ',' in v or '-' in v: raise ValueError('Use one port or any in this profile')
        if f.get('dport')=='8443': raise ValueError('Management traffic is protected')
        for k in ('threshold_count','threshold_seconds'):
            if f.get(k) and not 1<=int(f[k])<=1000000: raise ValueError('Invalid threshold')
        if f.get('threshold_track','by_src') not in ('by_src','by_dst'): raise ValueError('Invalid threshold track')
        if f.get('threshold_type','both') not in ('both','limit','threshold'): raise ValueError('Invalid threshold type')
        if f.get('dir','->')!='->': raise ValueError('This profile inspects traffic toward the service')
    elif schema == 'waf':
        for k in ('pattern','msg'):
            if any(c in f.get(k,'') for c in ('"','\\')): raise ValueError('Quotes/backslashes are not supported in this form')
        if str(f.get('status','403')) not in ('403','406','429'): raise ValueError('Invalid response status')
    return f


def candidate(device, state, payload):
    if not isinstance(payload,dict) or payload.keys()-{'operation','kind','id','name','enabled','fields','position'}: raise ValueError('Invalid operation')
    operation=payload.get('operation');kind=payload.get('kind','rule');bucket={'rule':'rules','object':'objects','nat':'nat'}.get(kind)
    result=copy.deepcopy(state)
    if operation=='rollback':
        if not state['history']: raise ValueError('No previous revision')
        previous=state['history'][-1]['previous']
        for k in ('rules','objects','nat'): result[k]=copy.deepcopy(previous[k])
    elif operation in ('upsert','delete','move') and bucket:
        if device!='fw' and kind!='rule': raise ValueError('Unsupported policy kind')
        rows=result[bucket];identifier=payload.get('id')
        index=next((i for i,r in enumerate(rows) if r['id']==identifier),None)
        if operation=='upsert':
            name=payload.get('name','').strip();safe_text(name)
            if not 1<=len(name)<=80: raise ValueError('Policy name is required (maximum 80 characters)')
            if identifier and index is None: raise ValueError('Policy no longer exists')
            if type(payload.get('enabled',True)) is not bool: raise ValueError('Invalid enabled state')
            fields=validate_fields(device,kind,payload.get('fields'))
            row={'id': identifier or uuid.uuid4().hex[:12], 'name':name,'enabled':payload.get('enabled',True),'fields':fields}
            # Stable IDs persist across edits/reloads and cannot collide with built-in rules.
            history_ids=[r['rule_id'] for h in state['history'] for key in ('rules','objects','nat') for r in h.get('previous',{}).get(key,[])]
            row['rule_id']=rows[index]['rule_id'] if index is not None else max(state.get('next_rule_id',9000001),max([r['rule_id'] for r in rows]+history_ids+[9000000])+1)
            if index is None: result['next_rule_id']=row['rule_id']+1
            if index is not None: rows[index]=row
            elif len(rows)>=100: raise ValueError('Maximum 100 entries in this profile')
            else: rows.append(row)
        else:
            if index is None: raise ValueError('Policy no longer exists')
            row=rows.pop(index)
            if operation=='move':
                pos=payload.get('position')
                if type(pos) is not int or not 0<=pos<=len(rows): raise ValueError('Invalid position')
                rows.insert(pos,row)
    else: raise ValueError('Unsupported operation')
    result['version']=state['version']+1
    return result


def compile_policy(device,state):
    if device=='fw':
        lines=['add table inet xoc_policy','delete table inet xoc_policy','table inet xoc_policy {']
        names=set()
        for row in state['objects']:
            f=row['fields'];name=f['name']
            if name in names: raise ValueError('Duplicate object name')
            names.add(name)
            lines.append('set %s { type %s; flags interval; elements = { %s }; }' % (name,f['type'],f['elements']))
        lines += ['chain forward { type filter hook forward priority -5; policy accept;',
                  'ip saddr 172.29.10.20 ip daddr 172.29.12.80 tcp dport 8443 return',
                  'ip saddr 172.29.12.80 ip daddr 172.29.10.20 tcp sport 8443 return']
        for row in state['rules']:
            if not row['enabled']: continue
            f=dict(row['fields'],chain='forward',position='bottom',log=False)
            # Legacy generators retain canonical field ordering; object ports need a typed extension.
            sport=f.pop('sport','')
            group=f.get('dport','') if f.get('dport','').startswith('@') else None
            if group: f['dport']='65535'
            text=fw_builders.build_filter_cmd(f).split(' forward ',1)[1]
            if group: text=text.replace('dport 65535','dport '+group)
            if sport: text=text.replace('counter',f['proto']+' sport '+sport+' counter',1)
            if row['fields'].get('log'):
                text=text.replace('counter ', 'counter log prefix "[xoc-fw] '+row['fields'].get('action','accept').upper()+' " group 10 snaplen 128 queue-threshold 1 ')
            lines.append(text+' comment "xoc:'+row['id']+'"')
        lines += ['}','}','add table ip xoc_nat','delete table ip xoc_nat','table ip xoc_nat {',
                  'chain prerouting { type nat hook prerouting priority -110; policy accept;',
                  'ip saddr 172.29.10.20 tcp dport 8443 return']
        for row in state['nat']:
            if row['enabled'] and row['fields'].get('kind','dnat')=='dnat':
                lines.append(fw_builders.build_nat_cmd(row['fields']).split(' prerouting ',1)[1]+' comment "xoc:'+row['id']+'"')
        lines += ['}','chain postrouting { type nat hook postrouting priority 90; policy accept;',
                  'ip saddr 172.29.10.20 tcp dport 8443 return','ip daddr 172.29.10.20 tcp sport 8443 return']
        for row in state['nat']:
            if row['enabled'] and row['fields'].get('kind') in ('snat','masquerade'):
                lines.append(fw_builders.build_nat_cmd(row['fields']).split(' postrouting ',1)[1]+' comment "xoc:'+row['id']+'"')
        return '\n'.join(lines+['}','}'])+'\n'
    lines=[]
    for row in state['rules']:
        if not row['enabled']: continue
        f=dict(row['fields'])
        if device=='ips':
            f.update(sid=row['rule_id'],rev=state['version']+1,msg=row['name'])
            if f.get('content'): f['content']=f['content'].replace(';','|3B|')
            if f.get('dport','any') in ('','any') and f.get('proto','http') not in ('icmp','ip'):
                f['dport']='[0:8442,8444:65535]'
            if f.get('proto')=='ip': raise ValueError('Use a specific protocol to preserve management access')
            lines.append(ips_builders.build_rule(f))
        else:
            f.update(id=row['rule_id'],msg=row['name']);lines.append(waf_builders.build_secrule(f))
    return '\n'.join(lines)+'\n'


def tail(path,limit=50):
    try:
        with Path(path).open('rb') as stream:
            stream.seek(0,2);size=stream.tell();stream.seek(max(0,size-65536));data=stream.read(65536).decode('utf-8','replace')
        return data.splitlines()[-limit:]
    except FileNotFoundError: return []
