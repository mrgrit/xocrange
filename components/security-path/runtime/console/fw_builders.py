"""Selected pure builders from nft_edu_gui; source hashes in console-source.json.
No legacy HTTP server, training/scoring or agent configuration is shipped.
"""
import re

def build_filter_cmd(p):
    """폼 입력 → nft add/insert rule 명령 문자열 생성 (실행 X)."""
    (family, table) = ('inet', 'six_filter')
    chain = p.get('chain', 'input')
    if chain not in ('input', 'forward', 'output'):
        raise ValueError('chain 은 input/forward/output 만 가능')
    parts = []
    if p.get('iif'):
        parts.append('iifname "%s"' % _safe(p['iif']))
    if p.get('oif'):
        parts.append('oifname "%s"' % _safe(p['oif']))
    if p.get('saddr'):
        parts.append('ip saddr %s' % _addr_or_set(p['saddr']))
    if p.get('daddr'):
        parts.append('ip daddr %s' % _addr_or_set(p['daddr']))
    proto = p.get('proto', '')
    if proto in ('tcp', 'udp'):
        if p.get('dport'):
            parts.append('%s dport %s' % (proto, _safe_port(p['dport'])))
        elif p.get('sport'):
            parts.append('%s sport %s' % (proto, _safe_port(p['sport'])))
        else:
            parts.append('ip protocol %s' % proto)
    elif proto == 'icmp':
        parts.append('ip protocol icmp')
    if p.get('ct_state'):
        parts.append('ct state %s' % _safe(p['ct_state']))
    if p.get('limit_rate'):
        over = 'over ' if p.get('limit_over') else ''
        parts.append('limit rate %s%s' % (over, _safe_rate(p['limit_rate'])))
    parts.append('counter')
    if p.get('log'):
        prefix = _safe(p.get('log_prefix') or 'EDU: ')
        parts.append('log prefix "%s"' % prefix)
    action = p.get('action', 'accept')
    if action not in ('accept', 'drop', 'reject'):
        raise ValueError('action 은 accept/drop/reject')
    parts.append(action)
    verb = 'insert' if p.get('position') == 'top' else 'add'
    body = ' '.join(parts)
    return 'nft %s rule %s %s %s %s' % (verb, family, table, chain, body)

def build_nat_cmd(p):
    (family, table) = ('ip', 'six_nat')
    kind = p.get('kind', 'dnat')
    if kind == 'dnat':
        chain = 'prerouting'
        parts = ['iifname "%s"' % _safe(p.get('iif', 'eth0'))]
        proto = p.get('proto', 'tcp')
        if proto not in ('tcp', 'udp'):
            raise ValueError('proto tcp/udp')
        parts.append('%s dport %s' % (proto, _safe_port(p['dport'])))
        parts.append('counter')
        tgt = '%s:%s' % (_safe_addr(p['to_ip']), _safe_port(p['to_port']))
        parts.append('dnat to %s' % tgt)
        return 'nft add rule %s %s %s %s' % (family, table, chain, ' '.join(parts))
    elif kind in ('snat', 'masquerade'):
        chain = 'postrouting'
        parts = ['oifname "%s"' % _safe(p.get('oif', 'eth1'))]
        if p.get('saddr'):
            parts.append('ip saddr %s' % _safe_addr(p['saddr']))
        parts.append('counter')
        if kind == 'snat':
            parts.append('snat to %s' % _safe_addr(p['to_ip']))
        else:
            parts.append('masquerade')
        return 'nft add rule %s %s %s %s' % (family, table, chain, ' '.join(parts))
    raise ValueError('kind dnat/snat/masquerade')

_ADDR_RE = re.compile('^[0-9a-fA-F:.\\/,{} -]+$')

_PORT_RE = re.compile('^[0-9,{} -]+$')

_TOK_RE = re.compile('^[A-Za-z0-9_,./: -]+$')

def _safe(s):
    s = str(s)
    if not _TOK_RE.match(s):
        raise ValueError('허용되지 않는 문자: %r' % s)
    return s

def _safe_addr(s):
    s = str(s).strip()
    if not _ADDR_RE.match(s):
        raise ValueError('주소 형식 오류: %r' % s)
    return s

def _safe_port(s):
    s = str(s).strip()
    if not _PORT_RE.match(s):
        raise ValueError('포트 형식 오류: %r' % s)
    return s

_RATE_RE = re.compile('^\\d+/(second|minute|hour|day)$')

def _safe_rate(s):
    s = str(s).strip()
    if not _RATE_RE.match(s):
        raise ValueError('rate 형식 오류 (예: 5/minute): %r' % s)
    return s

_SETNAME_RE = re.compile('^[A-Za-z_][A-Za-z0-9_]{0,31}$')

SET_TYPES = {'ipv4_addr': 'IP 주소 그룹', 'inet_service': '포트 그룹'}

def _safe_setname(s):
    s = str(s).strip()
    if not _SETNAME_RE.match(s):
        raise ValueError('그룹 이름은 영문/숫자/_ 만 (첫 글자 영문/_), 최대 32자: %r' % s)
    return s

def _addr_or_set(s):
    """주소 또는 @그룹이름. 룰에서 saddr/daddr 에 그룹 참조 허용."""
    s = str(s).strip()
    if s.startswith('@'):
        return '@' + _safe_setname(s[1:])
    return _safe_addr(s)

def _safe_elements(s, typ):
    items = [x for x in re.split('[ ,]+', str(s)) if x]
    out = []
    for it in items:
        out.append(_safe_addr(it) if typ == 'ipv4_addr' else _safe_port(it))
    if not out:
        raise ValueError('구성원(elements)이 비어 있습니다')
    return out

def build_set_cmds(p):
    """폼 → named set 생성/구성원 추가 명령 (실행 X)."""
    name = _safe_setname(p.get('name', ''))
    typ = p.get('type', 'ipv4_addr')
    if typ not in SET_TYPES:
        raise ValueError('종류는 ipv4_addr / inet_service')
    elems = _safe_elements(p.get('elements', ''), typ)
    create = 'nft add set inet six_filter %s { type %s ; }' % (name, typ)
    element = 'nft add element inet six_filter %s { %s }' % (name, ', '.join(elems))
    return {'create': create, 'element': element, 'commands': create + '\n' + element}
