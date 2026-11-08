"""Selected pure builders from suricata_edu_gui; source hashes in console-source.json.
No legacy HTTP server, training/scoring or agent configuration is shipped.
"""
import re

_RULE_HEAD_RE = re.compile('^\\s*(?P<action>alert|drop|pass|reject)\\s+(?P<proto>\\S+)\\s+(?P<src>\\S+)\\s+(?P<sport>\\S+)\\s+(?P<dir>->|<>)\\s+(?P<dst>\\S+)\\s+(?P<dport>\\S+)\\s*\\((?P<opts>.*)\\)\\s*$')

def parse_rule(line):
    """Suricata 룰 한 줄 → 구조 분해. 실패 시 {'error':...}."""
    line = line.strip()
    m = _RULE_HEAD_RE.match(line)
    if not m:
        return {'error': '룰 헤더를 인식할 수 없습니다.', 'raw': line}
    d = m.groupdict()
    opts_raw = d.pop('opts')
    (opts, buf, in_q) = ([], '', False)
    for ch in opts_raw:
        if ch == '"':
            in_q = not in_q
        if ch == ';' and (not in_q):
            if buf.strip():
                opts.append(buf.strip())
            buf = ''
        else:
            buf += ch
    if buf.strip():
        opts.append(buf.strip())
    parsed_opts = []
    for o in opts:
        if ':' in o:
            (k, v) = o.split(':', 1)
            parsed_opts.append({'k': k.strip(), 'v': v.strip()})
        else:
            parsed_opts.append({'k': o.strip(), 'v': None})
    sid = next((o['v'] for o in parsed_opts if o['k'] == 'sid'), None)
    msg = next((o['v'].strip('"') for o in parsed_opts if o['k'] == 'msg' and o['v']), None)
    d['options'] = parsed_opts
    d['sid'] = sid
    d['msg'] = msg
    d['raw'] = line
    return d

HTTP_BUFFERS = {'http.uri', 'http.user_agent', 'http.host', 'http.method', 'http.header', 'http.request_body', 'http.response_body', 'http.cookie', 'dns.query', 'tls.sni'}

def build_rule(p):
    """폼 입력 → Suricata 룰 한 줄 (실행 X)."""
    action = p.get('action', 'alert')
    if action not in ('alert', 'drop', 'pass', 'reject'):
        raise ValueError('action 은 alert/drop/pass/reject')
    proto = _tok(p.get('proto', 'http'))
    src = _net(p.get('src') or 'any')
    sport = _tok(p.get('sport') or 'any')
    direction = p.get('dir', '->')
    if direction not in ('->', '<>'):
        raise ValueError('방향은 -> 또는 <>')
    dst = _net(p.get('dst') or 'any')
    dport = _tok(p.get('dport') or 'any')
    opts = []
    msg = p.get('msg') or 'Custom IPS rule'
    opts.append('msg:"%s"' % _msg(msg))
    flow = p.get('flow')
    if flow:
        opts.append('flow:%s' % _tok(flow))
    buf = p.get('buffer')
    content = p.get('content')
    pcre = p.get('pcre')
    if buf and buf in HTTP_BUFFERS:
        opts.append(buf)
    if content:
        neg = '!' if p.get('content_negate') else ''
        opts.append('content:%s"%s"' % (neg, _content(content)))
        if p.get('nocase'):
            opts.append('nocase')
    if pcre:
        opts.append('pcre:"%s"' % _pcre(pcre))
    if p.get('threshold_count'):
        track = _tok(p.get('threshold_track') or 'by_src')
        cnt = int(p['threshold_count'])
        sec = int(p.get('threshold_seconds') or 60)
        ttype = _tok(p.get('threshold_type') or 'both')
        opts.append('threshold:type %s, track %s, count %d, seconds %d' % (ttype, track, cnt, sec))
    if p.get('classtype'):
        opts.append('classtype:%s' % _tok(p['classtype']))
    sid = int(p.get('sid') or next_sid())
    opts.append('sid:%d' % sid)
    opts.append('rev:%d' % int(p.get('rev') or 1))
    body = '; '.join(opts)
    return '%s %s %s %s %s %s %s (%s;)' % (action, proto, src, sport, direction, dst, dport, body)

def _tok(s):
    s = str(s).strip()
    if not re.match('^[A-Za-z0-9_,./:\\$!\\[\\]> <-]+$', s):
        raise ValueError('허용되지 않는 값: %r' % s)
    return s

def _net(s):
    s = str(s).strip()
    if not re.match('^[A-Za-z0-9_,./:\\$!\\[\\] -]+$', s):
        raise ValueError('네트워크 형식 오류: %r' % s)
    return s

def _msg(s):
    return re.sub('["\\\\;()]', '', str(s))[:120]

def _content(s):
    return re.sub('["]', '', str(s))[:200]

def _pcre(s):
    return re.sub('["]', '', str(s))[:200]
