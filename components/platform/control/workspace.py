"""Authenticated C4/C5 readers; the web process has no Docker or host access."""
from datetime import datetime, timezone
import json
from pathlib import Path
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.http import require_GET
from .security import protected, ROLES
from . import entitlements


def access(component, action='register', **resource):
    if not entitlements.paid(component) and not resource:
        return entitlements.authorize(None, component, action)
    directory = getattr(settings, 'ENTITLEMENT_DIR', '/run/xoc-platform/entitlements')
    grant = entitlements.load(directory, '0.1.0')
    return entitlements.authorize(grant, component, action, **resource)


def document(name, default):
    path = Path(getattr(settings, name, default))
    with path.open('rb') as stream:
        raw = stream.read(1048577)
    if len(raw) > 1048576:
        raise ValueError('Document too large')
    return json.loads(raw)


def registry():
    value = document('REGISTRY_FILE', '/run/xoc-platform/registry.json')
    if not isinstance(value, dict) or value.get('schema_version') != 'xoc.registry/0.1.0':
        raise ValueError('Unsupported registry')
    return value


def panels(data, role):
    selected = {c['id'] for c in data['components']}
    allowed = set()
    for component in data['components']:
        try:
            access(component)
            allowed.add(component['id'])
        except (OSError, ValueError, KeyError, TypeError):
            pass
    return [p for p in data['panels'] if p['component_id'] in selected & allowed and p['permission'] in ROLES.get(role, set())]


@require_GET
@protected('registry.read')
def module_status(request, identifier):
    """Owned status route disappears with the selected module's registration."""
    try:
        data = registry()
        component = next((c for c in data['components'] if c['id'] == identifier), None)
        if component is None:
            return JsonResponse({'error': 'component_not_installed'}, status=404)
        permission = access(component, 'read')
        return JsonResponse({'component': component, 'access': permission,
                             'assets': [a for a in snapshot(data)['assets'] if a['component_id'] == identifier]})
    except entitlements.Denied as exc:
        return JsonResponse({'error': exc.code}, status=403)
    except (OSError, ValueError, KeyError, TypeError):
        return JsonResponse({'error': 'registry_unavailable'}, status=503)


def session_navigation(role):
    try:
        return panels(registry(), role)
    except (OSError, ValueError, KeyError, TypeError):
        return []


EDITION_LABELS = {'community': 'Community', 'live-fire': 'Live Fire', 'joint-force': 'Joint Force'}


def edition():
    """The edition this installation runs under, for display only. Access is decided by
    authorize(); an unreadable or untrusted license is shown as Community, never as paid."""
    directory = getattr(settings, 'ENTITLEMENT_DIR', '/run/xoc-platform/entitlements')
    try:
        grant = entitlements.load(directory, '0.1.0')
    except (entitlements.Denied, OSError, ValueError, KeyError, TypeError):
        return {'tier': 'community', 'label': EDITION_LABELS['community'], 'state': 'invalid'}
    if grant is None or grant.get('tier') not in EDITION_LABELS:
        return {'tier': 'community', 'label': EDITION_LABELS['community'], 'state': 'none'}
    return {'tier': grant['tier'], 'label': EDITION_LABELS[grant['tier']], 'state': 'expired' if grant['expired'] else 'active',
            'expires_at': grant.get('expires_at')}


def snapshot(data):
    checked = datetime.now(timezone.utc)
    observation, age, fresh = {}, None, False
    try:
        observation = document('OBSERVATION_FILE', '/run/xoc-observation/health.json')
        observed = datetime.fromisoformat(observation['observed_at'])
        age = (checked - observed).total_seconds()
        fresh = observation['schema_version'] == 'xoc.health/0.1.0' and observation['plan_id'] == data['plan_id'] and 0 <= age <= 45 and isinstance(observation.get('assets'), dict)
    except (OSError, ValueError, KeyError, TypeError):
        observation = {}
    assets = []
    for asset in data['assets']:
        health = {'state':'unknown','reason':'observation_stale' if age is not None else 'observation_unavailable'}
        if fresh:
            item = observation.get('assets', {}).get(asset['asset_id'], {})
            if not isinstance(item, dict):
                item = {}
            allowed = ('running','degraded','exited','paused','restarting','created','dead','missing','unknown')
            health = {'state':item.get('state') if item.get('state') in allowed else 'unknown'}
            if type(item.get('restarts')) is int and item['restarts'] >= 0:
                health['restarts'] = item['restarts']
            if isinstance(item.get('started_at'), str):
                health['started_at'] = item['started_at'][:40]
        assets.append(dict(asset, health=health))
    return {'assets':assets,'observation':{'fresh':fresh,'observed_at':observation.get('observed_at') if fresh else None,
            'age_seconds':round(age) if age is not None and age >= 0 else None,'max_age_seconds':45,'scope':'container_state'},
            'served_at':checked.isoformat(), 'edition':edition()}


LAB_SEGMENTS = [('ext', '외부망', '10.20.30.0/24', '외부 요청이 처음 닿는 구간. 공격 실습 단말이 여기 있습니다.'),
                ('pipe', '중계망', '10.20.31.0/24', '방화벽과 IPS만 잇는 구간.'),
                ('dmz', 'DMZ', '10.20.32.0/24', 'IPS와 웹 방화벽 사이. 웹 서비스의 앞단.'),
                ('int', '내부망', '10.20.40.0/24', '웹 방화벽 뒤. 실습 대상과 내부 서비스.'),
                ('office', '업무망', '10.20.70.0/24', '내부 근무자의 PC가 있는 구간. IPS 뒤.')]


@require_GET
@protected('registry.read')
def lab(request):
    """Where to practise: target names, the lab hosts and how to reach them. Read-only."""
    try:
        data = registry()
        config = settings.CONFIG.get('lab') or {}
        host, domain = settings.CONFIG['public_host'], config.get('domain')
        installed = {c['id'] for c in data['components']}
        targets = [{'id': t, 'names': [t + '.xoc.range'] + ([t + '.' + domain] if domain else [])} for t in config.get('targets', [])]
        names = [n for t in targets for n in t['names']]
        user, password = config.get('username'), config.get('password')
        endpoints = []
        if 'attacker' in installed and user and password:
            endpoints.append({'id': 'attacker', 'title': '공격 실습 단말', 'segment': 'ext', 'address': '10.20.30.202',
                              'ssh': f'ssh -p 2202 {user}@{host}', 'username': user, 'password': password,
                              'note': '교재의 공격 명령을 여기서 실행합니다. 보낸 요청은 방화벽·IPS·웹 방화벽을 지나 이 단말의 주소로 기록됩니다.',
                              'inside': [f'curl http://{names[0]}/' if names else None,
                                         f'ssh -p 2222 {user}@10.20.30.1' if 'office-pc' in installed else None]})
        if 'office-pc' in installed and user and password:
            endpoints.append({'id': 'office-pc', 'title': '업무용 PC', 'segment': 'office', 'address': '10.20.70.21',
                              'ssh': f'ssh -p 2222 {user}@{host}', 'username': user, 'password': password,
                              'note': '내부 근무자의 리눅스 PC입니다. 로그인·sudo·계정 변경 기록이 SIEM에 agent.name: office-pc01로 남습니다.',
                              'inside': []})
        for item in endpoints:
            item['inside'] = [x for x in item['inside'] if x]
        return JsonResponse({'host': host, 'domain': domain, 'targets': targets,
                             'hosts_line': (host + ' ' + ' '.join(names)) if names else None, 'endpoints': endpoints,
                             'siem': '/siem/' if settings.CONFIG.get('siem_available') else None,
                             'segments': [dict(id=i, title=t, subnet=n, role=r) for i, t, n, r in LAB_SEGMENTS
                                          if i != 'office' or 'office-pc' in installed or any('office' in a.get('zones', []) for a in data['assets'])],
                             'path': ['HTTPS 진입점', '방화벽', 'IPS', '웹 방화벽', '실습 대상']})
    except (OSError, ValueError, KeyError, TypeError):
        return JsonResponse({'error': 'registry_unavailable'}, status=503)


@require_GET
@protected('users.manage')
def license_status(request):
    """Administrators see the active license and what is installed. Display only."""
    try:
        grant = None
        try:
            grant = entitlements.load(getattr(settings, 'ENTITLEMENT_DIR', '/run/xoc-platform/entitlements'), '0.1.0')
        except (entitlements.Denied, OSError, ValueError, KeyError, TypeError):
            grant = None
        components = [{k: c.get(k) for k in ('id', 'title', 'version', 'commercial', 'minimum_tier')} for c in registry()['components']]
        return JsonResponse({'edition': edition(),
                             'license': {k: grant.get(k) for k in ('license_id', 'institution_id', 'range_id', 'domain', 'expires_at', 'modules')} if grant else None,
                             'components': components})
    except (OSError, ValueError, KeyError, TypeError):
        return JsonResponse({'error': 'registry_unavailable'}, status=503)


@require_GET
@protected('registry.read')
def inventory(request, screen='registry'):
    try:
        data = registry()
        if screen == 'noc' and not any(c['id'] == 'noc' for c in data['components']):
            return JsonResponse({'error':'component_not_installed'},status=404)
        result = {k:data[k] for k in ('schema_version','plan_id','components')}
        result.update(snapshot(data), panels=panels(data,request.user.profile.role), floor='2F')
        return JsonResponse(result)
    except (OSError, ValueError, KeyError, TypeError):
        return JsonResponse({'error':'registry_unavailable'},status=503)


@require_GET
@protected('content.read')
def library(request, article=None):
    try:
        data = registry(); selected = {c['id'] for c in data['components']}
        if 'academy-reader' not in selected:
            return JsonResponse({'error':'component_not_installed'},status=404)
        content = document('BUNDLE_FILE', '/run/xoc-platform/bundle.json')
        available = [a for a in content['articles'] if set(a['requires']) <= selected]
        allowed = {p['id']:p for p in panels(data,request.user.profile.role)}
        if article is not None:
            item = next((a for a in available if a['id'] == article), None)
            if item is None:
                return JsonResponse({'error':'not_found'},status=404)
            return JsonResponse(dict(item, related_panels=[allowed[p] for p in item['related_panels'] if p in allowed], bundle_version=content['version']))
        return JsonResponse({k:content[k] for k in ('schema_version','id','version','title')} | {
            'articles':[{k:a[k] for k in ('id','title','summary','minutes')} for a in available]})
    except (OSError, ValueError, KeyError, TypeError):
        return JsonResponse({'error':'content_unavailable'},status=503)
