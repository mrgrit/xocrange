"""Selected C4 panels and C5 assets. No discovery, remote URLs or tenant input."""
from datetime import datetime, timezone
import json
import re
import uuid

from .documents import validate
from .errors import XocError


SERVICE_LABELS = {
    'platform': ('Core 관리', 'platform'), 'ingress': ('HTTPS 진입점', 'gateway'),
    'fw': ('방화벽', 'firewall'), 'ips': ('침입 방지', 'ips'), 'web': ('웹 방화벽', 'waf'),
    'siem': ('Wazuh Manager', 'siem'), 'indexer': ('Wazuh Indexer', 'siem'),
    'dashboard': ('Wazuh Dashboard', 'siem'), 'lab-target': ('연결 시험용 타깃', 'target'),
    'lab-client': ('연결 시험용 클라이언트', 'client'),
    'office-pc': ('업무용 리눅스 PC', 'client'),
    'attacker': ('공격 실습 단말', 'client'),
    'm4-facility': ('시설 시뮬레이터', 'service'),
    'dvwa': ('DVWA', 'target'), 'juiceshop': ('OWASP Juice Shop', 'target'),
}


def registrations(manifests):
    panels, identifiers, routes = [], set(), set()
    owned_routes = {'portal':'/core/#portal','noc':('/core/#noc','/core/#datacenter'),'academy-reader':'/core/#academy',
                    'console-fw':'/core/#fw/policies','console-ips':'/core/#ips/policies',
                    'console-waf':'/core/#waf/policies','siem-ui':'/siem/'}
    for manifest in manifests:
        for panel in manifest.get('ui', []):
            validate(panel, 'c4-panel')
            if manifest.get('contracts', {}).get('C4') != '0.1.0':
                raise XocError('missing_contract', 'UI registrations require C4 v0.1.')
            owned = owned_routes.get(manifest['id'], '/core/#module/' + manifest['id'])
            if panel['route'] not in ((owned,) if isinstance(owned,str) else owned):
                raise XocError('ui_route_owner', 'A UI panel must use its component-owned local route.')
            if panel['id'] in identifiers or panel['route'] in routes:
                raise XocError('ui_conflict', 'UI identifiers and routes must have one selected owner.')
            identifiers.add(panel['id']); routes.add(panel['route'])
            panels.append(dict(panel, component_id=manifest['id']))
    return sorted(panels, key=lambda p: (p['order'], p['id']))


def build_registry(planned, installation_id):
    namespace = uuid.UUID(installation_id)
    metadata = planned['registry']
    assets = []
    for service, component in sorted(metadata['service_owners'].items()):
        title, kind = SERVICE_LABELS.get(service, (service, 'service'))
        if any(t['service'] == service for t in metadata['targets']):
            kind = 'target'
        asset = dict(schema_version='xoc.asset/0.1.0',
                     asset_id='asset-' + uuid.uuid5(namespace, component + '/' + service).hex,
                     component_id=component, service=service, title=title, kind=kind, floor='2F',
                     zones=sorted(planned['compose']['services'][service]['networks']),
                     tenant_id='community', range_id='local')
        assets.append(validate(asset, 'c5-asset'))
    return dict(schema_version='xoc.registry/0.1.0', plan_id=planned['lock']['plan_id'],
                installation_id=installation_id, components=metadata['components'],
                panels=metadata['panels'], assets=assets)


def observe(engine, project, registry):
    """Host-only fixed Docker reads; publish no environment, mounts, logs or secrets."""
    checked = datetime.now(timezone.utc).isoformat()
    result = dict(schema_version='xoc.health/0.1.0', plan_id=registry['plan_id'],
                  observed_at=checked, provider='docker-state', assets={})
    expected = {a['service']: a['asset_id'] for a in registry['assets']}
    for identifier in expected.values():
        result['assets'][identifier] = {'state': 'missing', 'restarts': 0}
    try:
        ids = engine.run(['ps', '-aq', '--filter', 'label=com.docker.compose.project=' + project], timeout=10).split()
        if len(ids) > 128 or any(not re.fullmatch('[0-9a-f]{12,64}', v) for v in ids):
            raise ValueError('Unexpected container inventory')
        # Format selects only reviewed fields, including the project/service labels.
        fmt = ('{"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
               '"service":{{json (index .Config.Labels "com.docker.compose.service")}},'
               '"status":{{json .State.Status}},"health":{{if .State.Health}}{{json .State.Health.Status}}{{else}}null{{end}},'
               '"started_at":{{json .State.StartedAt}},"restarts":{{json .RestartCount}}}')
        rows = engine.run(['inspect', '--format', fmt, *ids], timeout=10).splitlines() if ids else []
        seen = set()
        for raw in rows:
            row = json.loads(raw)
            name = row.get('service')
            if row.get('project') != project or name not in expected:
                continue
            if name in seen:
                result['assets'][expected[name]] = {'state': 'unknown', 'reason': 'multiple_containers'}
                continue
            seen.add(name)
            state = row['status']
            state = 'degraded' if state == 'running' and row['health'] in ('unhealthy', 'starting') else state
            state = state if state in ('running', 'degraded', 'exited', 'paused', 'restarting', 'created', 'dead') else 'unknown'
            result['assets'][expected[name]] = dict(state=state, restarts=int(row['restarts']), started_at=row['started_at'])
    except (XocError, ValueError, KeyError, TypeError):
        result['assets'] = {i: {'state': 'unknown', 'reason': 'observer_unavailable'} for i in expected.values()}
    return result
