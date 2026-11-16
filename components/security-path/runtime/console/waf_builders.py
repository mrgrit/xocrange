"""Selected pure builders from modsec_edu_gui; source hashes in console-source.json.
No legacy HTTP server, training/scoring or agent configuration is shipped.
"""
import ipaddress
import re

VARIABLES = ['REMOTE_ADDR', 'REQUEST_URI', 'ARGS', 'ARGS_NAMES', 'QUERY_STRING', 'REQUEST_BODY', 'REQUEST_HEADERS', 'REQUEST_HEADERS:User-Agent', 'REQUEST_COOKIES', 'REQUEST_FILENAME', 'REQUEST_LINE', 'REQUEST_HEADERS:Referer']

OPERATORS = ['@rx', '@contains', '@pm', '@streq', '@beginsWith', '@endsWith', '@ipMatch']

TRANSFORMS = ['lowercase', 'urlDecodeUni', 'removeNulls', 'compressWhitespace', 'none']

ACTIONS = ['deny', 'pass', 'drop', 'block']

SEVERITIES = ['CRITICAL', 'ERROR', 'WARNING', 'NOTICE']

def _id_in(s):
    return bool(re.match('^\\d+$', str(s)))

def build_secrule(p):
    var = p.get('variable', 'REQUEST_URI')
    if var not in VARIABLES:
        raise ValueError('허용되지 않는 변수')
    op = p.get('operator', '@rx')
    if op not in OPERATORS:
        raise ValueError('허용되지 않는 연산자')
    pattern = _pat(p.get('pattern', ''))
    if not pattern:
        raise ValueError('탐지 패턴이 비어 있습니다')
    # Client address blocking (xOC addition): REMOTE_ADDR only with @ipMatch and a list of up to
    # 8 IP addresses or networks. The web entry sets REMOTE_ADDR from the ingress's client header.
    if (var == 'REMOTE_ADDR') != (op == '@ipMatch'):
        raise ValueError('클라이언트 주소는 IP 일치(@ipMatch)로만 검사합니다')
    if op == '@ipMatch':
        items = [x.strip() for x in pattern.split(',')]
        if not 1 <= len(items) <= 8:
            raise ValueError('IP 주소는 1~8개까지')
        try:
            pattern = ','.join(str(ipaddress.ip_network(x, strict=False)) if '/' in x else str(ipaddress.ip_address(x)) for x in items)
        except ValueError:
            raise ValueError('IP 주소 또는 네트워크(CIDR)만 쓸 수 있습니다')
    phase = str(p.get('phase', '2'))
    if phase not in ('1', '2'):
        raise ValueError('phase 는 1 또는 2')
    action = p.get('action', 'deny')
    if action not in ACTIONS:
        raise ValueError('허용되지 않는 액션')
    sev = p.get('severity', 'CRITICAL')
    if sev not in SEVERITIES:
        raise ValueError('허용되지 않는 severity')
    transforms = p.get('transforms') or ['none']
    if isinstance(transforms, str):
        transforms = [transforms]
    tparts = []
    for t in transforms:
        if t not in TRANSFORMS:
            raise ValueError('허용되지 않는 transform: %s' % t)
        tparts.append('t:%s' % t)
    rid = p.get('id')
    rid = int(rid) if _id_in(rid) else next_id()
    msg = _msg(p.get('msg') or 'Custom WAF rule')
    acts = ['id:%d' % rid, 'phase:%s' % phase] + tparts + [action]
    if action == 'deny':
        acts.append('status:%s' % str(p.get('status', '403')))
    acts += ['log', "msg:'%s'" % msg, "severity:'%s'" % sev]
    return 'SecRule %s "%s %s" "%s"' % (var, op, pattern, ','.join(acts))

_SECRULE_RE = re.compile('^\\s*SecRule\\s+(?P<vars>\\S+)\\s+"(?P<opval>(?:[^"\\\\]|\\\\.)*)"\\s+"(?P<acts>(?:[^"\\\\]|\\\\.)*)"\\s*$')

def parse_secrule(line):
    line = line.strip()
    m = _SECRULE_RE.match(line)
    if not m:
        return {'error': 'SecRule 형식을 인식할 수 없습니다 (한 줄 SecRule 만 지원).', 'raw': line}
    vars_ = m.group('vars')
    opval = m.group('opval').strip()
    op_m = re.match('^(@\\w+)\\s*(.*)$', opval)
    operator = op_m.group(1) if op_m else '(implicit @rx)'
    pattern = op_m.group(2) if op_m else opval
    (acts, cur, in_q) = ([], '', False)
    for ch in m.group('acts'):
        if ch == "'":
            in_q = not in_q
        if ch == ',' and (not in_q):
            if cur.strip():
                acts.append(cur.strip())
            cur = ''
        else:
            cur += ch
    if cur.strip():
        acts.append(cur.strip())
    adict = {}
    for a in acts:
        if ':' in a:
            (k, v) = a.split(':', 1)
            adict[k.strip()] = v.strip().strip("'")
        else:
            adict[a.strip()] = True
    return {'variables': vars_, 'operator': operator, 'pattern': pattern, 'actions': acts, 'id': adict.get('id'), 'phase': adict.get('phase'), 'msg': adict.get('msg'), 'severity': adict.get('severity'), 'raw': line}

def _pat(s):
    return str(s).replace('"', '')[:300]

def _msg(s):
    return re.sub('[\'\\"\\\\]', '', str(s))[:120]
