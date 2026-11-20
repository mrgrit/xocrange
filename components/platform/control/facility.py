"""Facility state from the M4 facility module and the learner's requests to it (ADR 0014).

Core does not simulate facilities and creates no faults. It shows the state the module
wrote, after checking every field, and hands the module a request file. Without the
module the datacenter shows baseline values only (ADR 0010).
"""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import secrets
from django.conf import settings
from django.core.exceptions import ValidationError
from django.http import JsonResponse
from django.views.decorators.http import require_GET, require_POST
from .security import protected, audit
from . import entitlements

CAPABILITY = 'facility-state'
STALE_SECONDS = 30
STATE_LIMIT = 524288
REQUEST_LIMIT = 64          # waiting request files; the module handles one within a second or two
REQUEST_TTL = timedelta(minutes=10)
ID = re.compile(r'[a-z][a-z0-9-]{0,63}')
KEY = re.compile(r'[a-z][a-z0-9_]{0,47}')
RID = re.compile(r'[0-9a-f]{32}')
TARGET = re.compile(r'\*|[a-z][a-z0-9-]{0,63}|[1-9]F|B1|SITE')
ALARM = re.compile(r'[A-Za-z][A-Za-z0-9_.-]{0,63}')
AISLE = re.compile(r'[A-Z][A-Z0-9-]{0,7}')
FLOOR = re.compile(r'B1|SITE|[1-9]F')
STAMP = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z')
UNSAFE = re.compile(r'[\x00-\x1f<>]')
STATUS = ('normal', 'warning', 'critical', 'off')
SYSTEMS = ('power', 'cooling', 'security', 'fire', 'compute', 'network', 'storage')
COURSE = re.compile(r'[a-z0-9-]{0,32}')
ACTIONS = {'inject': ('fault', 'target', 'minutes'), 'clear': ('handle',), 'clear_all': (), 'shed': ('group',),
           'restore': ('group',), 'time_scale': ('value',), 'operate': ('op', 'target'), 'drill_start': ('drill',),
           'drill_stop': ()}
OPTIONAL = {'operate': ('value',)}


def _state_dir():
    return Path(getattr(settings, 'FACILITY_STATE_DIR', '/run/xoc-facility'))


def _request_dir():
    return Path(getattr(settings, 'FACILITY_REQUEST_DIR', '/run/xoc-facility-requests'))


def _fail():
    raise ValueError('facility_state')


def _obj(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= value.keys() or not value.keys() <= set(required) | set(optional):
        _fail()
    return value


def _text(value, limit, empty=False):
    if not isinstance(value, str) or len(value) > limit or (not value and not empty) or UNSAFE.search(value):
        _fail()
    return value


def _match(value, pattern):
    if not isinstance(value, str) or not pattern.fullmatch(value):
        _fail()
    return value


def _number(value, low=-1e9, high=1e9):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value or not low <= value <= high:
        _fail()
    return value


def _list(value, limit):
    if not isinstance(value, list) or len(value) > limit:
        _fail()
    return value


def _choice(value, options):
    if not isinstance(value, str) or value not in options:
        _fail()
    return value


def _metric(value):
    item = _obj(value, ('key', 'label', 'value', 'unit'))
    reading = item['value']
    if isinstance(reading, str):
        _text(reading, 60)
    elif not isinstance(reading, bool):
        _number(reading)
    return {'key': _match(item['key'], KEY), 'label': _text(item['label'], 60), 'value': reading, 'unit': _text(item['unit'], 16, empty=True)}


def _targets(value):
    return [{'id': _match(t['id'], TARGET), 'title': _text(t['title'], 80)} for t in (_obj(x, ('id', 'title')) for x in _list(value, 32))]


def _integer(value, low, high):
    if isinstance(value, bool) or not isinstance(value, int):
        _fail()
    return int(_number(value, low, high))


def _operation(o):
    row = {'id': _match(o['id'], KEY), 'title': _text(o['title'], 80), 'system': _choice(o['system'], SYSTEMS),
           'minutes': _integer(o['minutes'], 0, 240),
           'needs_drain': o['needs_drain'] if isinstance(o['needs_drain'], bool) else _fail(),
           'targets': _targets(o['targets'])}
    if 'value' in o:
        v = _obj(o['value'], ('min', 'max', 'unit', 'default'))
        row['value'] = {'min': _number(v['min'], 0.1, 120), 'max': _number(v['max'], 0.1, 120),
                        'unit': _text(v['unit'], 16, empty=True), 'default': _number(v['default'], 0.1, 120)}
    return row


def _drill(d):
    if d is None:
        return None
    d = _obj(d, ('id', 'title', 'brief', 'status', 'started_at', 'ended_at', 'elapsed_min', 'minutes', 'open_faults'))
    return {'id': _match(d['id'], KEY), 'title': _text(d['title'], 120), 'brief': _text(d['brief'], 600, empty=True),
            'status': _choice(d['status'], ('running', 'finished', 'stopped')), 'started_at': _match(d['started_at'], STAMP),
            'ended_at': None if d['ended_at'] is None else _match(d['ended_at'], STAMP),
            'elapsed_min': None if d['elapsed_min'] is None else _number(d['elapsed_min'], 0),
            'minutes': _integer(d['minutes'], 1, 480), 'open_faults': _integer(d['open_faults'], 0, 64)}


def checked(value):
    """The module's document, field by field (contract xoc.facility-state/0.1.0). Anything
    outside the contract rejects the whole document; nothing from it is shown. Operator
    actions, drills and work in progress are optional parts of the same contract."""
    top = _obj(value, ('schema_version', 'generated_at', 'sequence', 'time_scale', 'load_source', 'summary', 'assets',
                       'aisles', 'alarms', 'faults', 'catalog', 'handled', 'events'), ('drill', 'work'))
    if top['schema_version'] != 'xoc.facility-state/0.1.0' or isinstance(top['sequence'], bool) or not isinstance(top['sequence'], int) or top['sequence'] < 0:
        _fail()
    catalog = _obj(top['catalog'], ('faults', 'shed_groups'), ('operations', 'drills'))
    extra = {
        'drill': _drill(top.get('drill')),
        'work': [{'op': _match(w['op'], KEY), 'title': _text(w['title'], 80), 'target': _match(w['target'], TARGET),
                  'target_title': _text(w['target_title'], 80), 'minutes_left': _number(w['minutes_left'], 0, 1e6)}
                 for w in (_obj(x, ('op', 'title', 'target', 'target_title', 'minutes_left')) for x in _list(top.get('work', []), 16))]}
    return extra | {
        'generated_at': _match(top['generated_at'], STAMP), 'sequence': top['sequence'],
        'time_scale': _number(top['time_scale'], 0.1, 120), 'load_source': _choice(top['load_source'], ('profile', 'measured')),
        'summary': [_metric(m) for m in _list(top['summary'], 24)],
        'assets': [{'id': _match(a['id'], ID), 'status': _choice(a['status'], STATUS), 'metrics': [_metric(m) for m in _list(a['metrics'], 12)],
                    **({'title': _text(a['title'], 60)} if 'title' in a else {})}
                   for a in (_obj(x, ('id', 'status', 'metrics'), ('title',)) for x in _list(top['assets'], 200))],
        'aisles': [{'id': _match(a['id'], AISLE), 'floor': _match(a['floor'], FLOOR), 'temp_c': _number(a['temp_c']), 'status': _choice(a['status'], STATUS),
                    'metrics': [_metric(m) for m in _list(a.get('metrics', []), 8)]}
                   for a in (_obj(x, ('id', 'floor', 'temp_c', 'status'), ('metrics',)) for x in _list(top['aisles'], 16))],
        'alarms': [{'id': _match(a['id'], ALARM), 'level': _choice(a['level'], ('warning', 'critical')),
                    'asset_id': None if a.get('asset_id') is None else _match(a['asset_id'], ID),
                    'message': _text(a['message'], 200), 'since': _match(a['since'], STAMP)}
                   for a in (_obj(x, ('id', 'level', 'message', 'since'), ('asset_id',)) for x in _list(top['alarms'], 64))],
        'faults': [{'handle': _match(f['handle'], RID), 'fault': _match(f['fault'], KEY), 'title': _text(f['title'], 120),
                    'target': _match(f['target'], TARGET), 'started_at': _match(f['started_at'], STAMP),
                    'expires_at': _match(f['expires_at'], STAMP), 'requested_by': _text(f['requested_by'], 150)}
                   for f in (_obj(x, ('handle', 'fault', 'title', 'target', 'started_at', 'expires_at', 'requested_by')) for x in _list(top['faults'], 32))],
        'catalog': {
            'faults': [{'id': _match(f['id'], KEY), 'title': _text(f['title'], 120), 'system': _choice(f['system'], SYSTEMS),
                        'targets': _targets(f['targets']),
                        'default_minutes': int(_number(f['default_minutes'], 1, 120))}
                       for f in (_obj(x, ('id', 'title', 'system', 'targets', 'default_minutes')) for x in _list(catalog['faults'], 128))],
            'operations': [_operation(_obj(x, ('id', 'title', 'system', 'minutes', 'needs_drain', 'targets'), ('value',)))
                           for x in _list(catalog.get('operations', []), 96)],
            'drills': [{'id': _match(d['id'], KEY), 'title': _text(d['title'], 120), 'brief': _text(d['brief'], 600, empty=True),
                        'course': _match(d['course'], COURSE) if d['course'] else '', 'level': _integer(d['level'], 1, 5),
                        'minutes': _integer(d['minutes'], 1, 480), 'time_scale': _number(d['time_scale'], 0.1, 120)}
                       for d in (_obj(x, ('id', 'title', 'brief', 'course', 'level', 'minutes', 'time_scale')) for x in _list(catalog.get('drills', []), 128))],
            'shed_groups': [{'id': _match(g['id'], ID), 'title': _text(g['title'], 80), 'impact': _text(g['impact'], 200),
                             'load_kw': _number(g['load_kw']), 'shed': g['shed'] if isinstance(g['shed'], bool) else _fail()}
                            for g in (_obj(x, ('id', 'title', 'impact', 'load_kw', 'shed')) for x in _list(catalog['shed_groups'], 16))]},
        'handled': [{'request_id': _match(h['request_id'], RID), 'status': _choice(h['status'], ('applied', 'rejected')),
                     'code': _match(h['code'], KEY), 'at': _match(h['at'], STAMP)}
                    for h in (_obj(x, ('request_id', 'status', 'code', 'at')) for x in _list(top['handled'], 64))],
        'events': [{'at': _match(e['at'], STAMP), 'kind': _choice(e['kind'], ('info', 'inject', 'clear', 'alarm', 'recover', 'action')),
                    'message': _text(e['message'], 240)}
                   for e in (_obj(x, ('at', 'kind', 'message')) for x in _list(top['events'], 50))]}


def module(data):
    """The installed module that holds the facility capability, or None."""
    return next((c for c in data['components'] if CAPABILITY in (c.get('requires') or {}).get('capabilities', [])), None)


def read(now=None):
    """(state, problem). state is the checked document; problem is None, 'absent', 'stale' or 'invalid'."""
    path = _state_dir()/'state.json'
    try:
        with path.open('rb') as stream:
            raw = stream.read(STATE_LIMIT + 1)
    except OSError:
        return None, 'absent'
    try:
        if len(raw) > STATE_LIMIT:
            raise ValueError()
        value = checked(json.loads(raw))
        stamp = datetime.fromisoformat(value['generated_at'].replace('Z', '+00:00'))
    except (ValueError, KeyError, TypeError, RecursionError, UnicodeError):
        return None, 'invalid'
    if (now or datetime.now(timezone.utc)) - stamp > timedelta(seconds=STALE_SECONDS):
        return value, 'stale'
    return value, None


def overview(data):
    """What the datacenter and the facility screen need: whether a simulator is installed and
    allowed, and its state. Never raises for a missing or broken module."""
    component = module(data)
    if component is None:
        return {'installed': False, 'simulator': False, 'reason': 'not_installed'}
    from .workspace import access
    try:
        grant = access(component, 'read')
    except entitlements.Denied as exc:
        return {'installed': True, 'simulator': False, 'reason': exc.code}
    state, problem = read()
    result = {'installed': True, 'simulator': state is not None and problem is None, 'reason': problem,
              'read_only': grant.get('mode') == 'read-only', 'module': {'id': component['id'], 'version': component['version']}}
    if state is not None:
        result['state'] = state
    return result


@require_GET
@protected('registry.read')
def state(request):
    from .workspace import registry
    try:
        value = overview(registry())
        value['can_operate'] = bool(value.get('simulator')) and not value.get('read_only') and request.user.profile.role in ('operator', 'admin')
        return JsonResponse(value)
    except (OSError, ValueError, KeyError, TypeError):
        return JsonResponse({'error': 'registry_unavailable'}, status=503)


def _prune(directory, handled, now):
    """Remove request files the module has answered, and ones nobody picked up."""
    waiting = 0
    for path in directory.iterdir():
        if not re.fullmatch(r'[0-9a-f]{32}\.json', path.name):
            continue
        try:
            old = now - datetime.fromtimestamp(path.stat().st_mtime, timezone.utc) > REQUEST_TTL
            if path.stem in handled or old:
                path.unlink()
            else:
                waiting += 1
        except OSError:
            pass
    return waiting


@require_POST
@protected('devices.preview')
def request_change(request):
    """Hand one request to the module. The module decides and reports the outcome in its state."""
    from .workspace import registry, access
    from .views import data as body
    try:
        value = body(request, ('action',), ('fault', 'target', 'minutes', 'handle', 'group', 'value', 'op', 'drill'))
        action = _choice(value['action'], tuple(ACTIONS))
        fields = ACTIONS[action]
        given = set(value) - {'action'}
        if not set(fields) <= given or not given <= set(fields) | set(OPTIONAL.get(action, ())):
            _fail()
        fields = tuple(fields) + tuple(k for k in OPTIONAL.get(action, ()) if k in given)
        document = {'schema_version': 'xoc.facility-request/0.1.0', 'request_id': secrets.token_hex(16),
                    'created_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                    'requested_by': _text(request.user.username, 150), 'action': action}
        if 'fault' in fields: document['fault'] = _match(value['fault'], KEY)
        if 'target' in fields: document['target'] = _match(value['target'], TARGET)
        if 'minutes' in fields:
            if isinstance(value['minutes'], bool) or not isinstance(value['minutes'], int): _fail()
            document['minutes'] = int(_number(value['minutes'], 1, 120))
        if 'handle' in fields: document['handle'] = _match(value['handle'], RID)
        if 'group' in fields: document['group'] = _match(value['group'], ID)
        if 'value' in fields: document['value'] = _number(value['value'], 0.1, 120)
        if 'op' in fields: document['op'] = _match(value['op'], KEY)
        if 'drill' in fields: document['drill'] = _match(value['drill'], KEY)
    except (ValueError, ValidationError):
        return JsonResponse({'error': 'invalid_input'}, status=400)
    target = document.get('fault') or document.get('op') or document.get('drill') or document.get('group') or document.get('handle') or ''
    try:
        component = module(registry())
        if component is None:
            return JsonResponse({'error': 'facility_module_not_installed'}, status=404)
        access(component, 'execute')
        state, problem = read()
        if state is None or problem is not None:
            return JsonResponse({'error': 'facility_simulator_unavailable'}, status=503)
        directory = _request_dir()
        if _prune(directory, {h['request_id'] for h in state['handled']}, datetime.now(timezone.utc)) >= REQUEST_LIMIT:
            return JsonResponse({'error': 'facility_requests_waiting'}, status=429)
        staged = directory/('.' + document['request_id'] + '.tmp')
        with open(staged, 'x', encoding='utf-8') as stream:
            json.dump(document, stream, ensure_ascii=False)
            stream.flush(); os.fsync(stream.fileno())
        os.chmod(staged, 0o644)
        staged.replace(directory/(document['request_id'] + '.json'))
    except entitlements.Denied as exc:
        audit(request, 'facility_' + action, 'denied', target)
        return JsonResponse({'error': exc.code}, status=403)
    except (OSError, ValueError, KeyError, TypeError):
        return JsonResponse({'error': 'facility_request_failed'}, status=503)
    audit(request, 'facility_' + action, 'requested', target,
          after={k: document[k] for k in ('request_id', 'fault', 'target', 'minutes', 'handle', 'group', 'value', 'op', 'drill') if k in document})
    return JsonResponse({'request_id': document['request_id']}, status=202)
