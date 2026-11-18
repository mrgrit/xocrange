"""Core visualization policy. Commercial floor data is never supplied by Core."""
from django.conf import settings
from django.http import JsonResponse
import re
from django.views.decorators.http import require_GET
from .security import protected
from .workspace import registry, snapshot, panels, document
from datetime import datetime, timezone
from pathlib import Path
import json


# 6F–8F are the requested academy, live-fire and student-company extension.
# xOC remains a separately named restricted operations area.
FLOORS = [
    ('B1', '전력 · 냉각 설비', 'INFRASTRUCTURE', 'community'),
    ('1F', '보안 로비', 'SECURITY LOBBY', 'live-fire'),
    ('2F', '일반 전산실', 'CORE SECURITY', 'community'),
    ('3F', 'AI 전산실', 'AI COMPUTE', 'live-fire'),
    ('4F', '운영 사무실', 'OPERATIONS', 'live-fire'),
    ('5F', 'AI 연구소', 'RESEARCH LAB', 'live-fire'),
    ('6F', '아카데미', 'ACADEMY', 'community'),
    ('7F', 'Live Fire', 'CYBER RANGE', 'live-fire'),
    ('8F', 'Agent Office', 'AGENT OFFICE', 'joint-force'),
    ('XOC', 'xOC 관제센터', 'JOINT OPERATIONS', 'joint-force'),
    ('SITE', '옥외 설비', 'OUTDOOR INFRASTRUCTURE', 'community'),
]

# Inherit the kt66 rack identities and positions; install-only Core management
# services share R-2F-02 while their commercial 4F workspace is unavailable.
RACKS = [
    dict(id='R-2F-01', title='네트워크 · 보안 · 웹 서비스', floor='2F', aisle='A', units=42, position=[3, 3]),
    dict(id='R-2F-02', title='SIEM · Core 관리', floor='2F', aisle='A', units=42, position=[3, 5]),
    # Lab switching (ADR 0010): the four lab bridges shown as switches, with the routing they carry.
    dict(id='R-2F-03', title='실습망 스위치 · 라우팅', floor='2F', aisle='A', units=42, position=[5.6, 3]),
]
# Facility display with baseline values (ADR 0010). The simulator and fault injection are M4.
FACILITY_FLOORS = ('B1', 'SITE')
FACILITY_CATALOG = Path(__file__).with_name('facility-catalog.json')


def facility_catalog():
    value = json.loads(FACILITY_CATALOG.read_text())
    if value.get('schema_version') != 'xoc.facility-catalog/0.1.0':
        raise ValueError('Unsupported facility catalog')
    return value


SEGMENT_TITLES = {'ext': '외부망', 'pipe': '중계망(Transit)', 'dmz': 'DMZ', 'int': '내부망', 'office': '업무망'}
SEGMENT_ROLES = {
    'ext': '외부에서 들어온 요청이 처음 닿는 구간입니다. 진입 게이트웨이(ingress)와 방화벽의 외부 인터페이스가 연결됩니다.',
    'pipe': '방화벽과 IPS 두 장비만 잇는 중계 구간입니다. 방화벽을 지난 트래픽만 IPS로 전달됩니다. 업계에서는 트랜짓 네트워크(transit network)라고 부릅니다.',
    'dmz': 'IPS와 웹 방화벽 사이의 구간입니다. 외부에 공개하는 웹 서비스의 앞단입니다.',
    'int': '웹 방화벽 뒤의 내부망입니다. 실습 타깃과 내부 서비스가 연결되며 외부로 직접 나가지 않습니다.',
    'office': '내부 근무자의 PC가 연결되는 업무망입니다. IPS 뒤에 있으며, 이 망의 PC는 웹 방화벽과 SIEM 에이전트 포트로만 나갈 수 있습니다.',
}
ROUTING_ROLES = {
    'ingress': '외부망의 HTTPS 진입점입니다. 외부 요청을 받아 방화벽 쪽으로 넘깁니다.',
    'fw': '외부망과 중계망을 잇는 라우터 역할도 합니다.',
    'ips': '중계망과 DMZ·업무망을 잇는 라우터 역할도 합니다.',
    'web': 'DMZ와 내부망을 잇는 리버스 프록시입니다.',
}
DESCRIPTIONS = {
    'ingress': '외부 HTTPS 연결을 받아 방화벽 → IPS → 웹 방화벽 순서의 보안 검사 경로로 전달하는 HTTPS 진입점(리버스 프록시)입니다.',
    'fw': 'nftables 방화벽입니다. FORWARD 필터 정책과 NAT로 네트워크 구간 사이의 접근을 제어합니다.',
    'ips': 'Suricata 인라인 침입 방지 장비입니다. NFQUEUE 경로의 패킷을 검사하고 적용된 규칙에 따라 탐지·차단합니다.',
    'web': 'Apache와 ModSecurity 기반 웹 방화벽입니다. 웹 요청을 검사하고 허용된 서비스로 전달하며 접근·오류·차단 로그를 기록합니다.',
    'siem': 'Wazuh Manager입니다. 수집된 보안 로그를 디코딩하고 탐지 규칙으로 분석해 경보(alert)와 원본 로그 보관 기록(archives)을 만듭니다.',
    'indexer': 'Wazuh Indexer입니다. 보안 이벤트와 경보를 색인·저장하고 대시보드의 검색 요청을 처리합니다.',
    'dashboard': 'Wazuh Dashboard입니다. 보안 이벤트의 검색·분석과 Wazuh 관리 화면을 제공합니다. Core와 별도 계정을 사용합니다.',
    'platform': 'Core 공통 관리 서비스입니다. 로그인·역할·감사·설치된 서비스 목록과 보안 장비 콘솔의 접근을 관리합니다.',
    'lab-client': '연결 시험용 클라이언트입니다. 보안 검사 경로를 통과하는 정상 요청과, 차단되어야 하는 시험 요청(탐지 시그니처 포함)을 보냅니다.',
    'office-pc': '업무망의 리눅스 PC입니다. 근무자 계정으로 SSH 로그인해 사용하며, 로그인·sudo·계정 변경 기록을 Wazuh 에이전트가 SIEM으로 보냅니다.',
    'lab-target': '연결 시험용 웹 타깃입니다. 정상 통신·접근 제한·경로 복구를 시험하는 응답 서버입니다.',
}


def device_metadata(asset, available_panels):
    service = asset['service']
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', service):
        raise ValueError('Invalid registered service')
    rack = 'R-2F-02' if service in ('siem', 'indexer', 'dashboard', 'platform') else 'R-2F-01'
    panel_id = {'fw':'fw', 'ips':'ips', 'web':'waf', 'siem':'siem', 'indexer':'siem',
                'dashboard':'siem', 'platform':'portal'}.get(service)
    panel = next((p for p in available_panels if p['id'] == panel_id), None)
    # Commands are text for the user's own SSH session, never executed by Core.
    selector = ('sudo docker ps -q --filter label=com.docker.compose.project=xoc-core-security-path '
                '--filter label=com.docker.compose.service=' + service)
    return dict(asset, rack_id=rack, description=DESCRIPTIONS.get(service, '선택 설치된 Core 서비스입니다.'),
                web_console=panel['route'] if panel else None,
                access={'kind':'container_via_host', 'direct_ssh':False,
                        'shell_command':'sudo docker exec -it "$(' + selector + ')" sh'})



# The host observer refreshes the lab network view every 60 s (service health every 15 s): each
# refresh starts dozens of short `ip`/`nsenter` processes that Sysmon records in the lab SIEM.
NETWORK_FRESH_SECONDS = 150


def network_observation(plan_id):
    """The host observer's lab network view, if fresh and for this installation."""
    try:
        value = document('NETWORK_FILE', '/run/xoc-observation/network.json')
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(value['observed_at'])).total_seconds()
        if value.get('schema_version') == 'xoc.network/0.1.0' and value.get('plan_id') == plan_id and 0 <= age <= NETWORK_FRESH_SECONDS \
                and isinstance(value.get('segments'), list):
            return value
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return None


def network_assets(network):
    """Switch devices for rack R-2F-03 from the observed lab bridges (read-only)."""
    out = []
    for segment in (network or {}).get('segments', []):
        if segment.get('id') not in SEGMENT_TITLES:
            continue
        bridge = segment.get('bridge') if isinstance(segment.get('bridge'), str) and re.fullmatch(r'[a-z0-9-]{1,15}', segment['bridge']) else None
        state = {'up': 'running', 'down': 'exited'}.get(segment.get('state'), 'unknown')
        out.append(dict(asset_id='net-' + segment['id'], service='sw-' + segment['id'], title='실습망 스위치 · ' + SEGMENT_TITLES[segment['id']],
                        kind='switch', rack_id='R-2F-03', floor='2F', zones=[segment['id']], health={'state': state},
                        description=SEGMENT_ROLES[segment['id']] + ' 실제로는 호스트의 Docker 브리지이며, 연결된 장비 사이의 프레임을 MAC 주소 표로 전달합니다.',
                        web_console=None, segment=segment,
                        access={'kind': 'host_readonly', 'direct_ssh': False,
                                'shell_command': ('ip -s link show ' + bridge + '\nbridge fdb show br ' + bridge) if bridge else ''}))
    return out


@require_GET
@protected('registry.read')
def endpoint(request, floor=None):
    try:
        data = registry()
        if not any(c['id'] == 'noc' for c in data['components']):
            return JsonResponse({'error':'component_not_installed'},status=404)
        if floor is not None and floor not in {f[0] for f in FLOORS}:
            return JsonResponse({'error':'not_found'},status=404)
        # No client tier/floor flags, query parameters or unverified license
        # strings can unlock a floor. Commercial providers follow C7 in K10.
        academy=any(c['id']=='academy-reader' for c in data['components'])
        allowed=['2F','B1','SITE']+(['6F'] if academy else [])
        if floor is not None and floor not in allowed:
            return JsonResponse({'error':'floor_unavailable'},status=403)
        if floor=='6F':
            return JsonResponse({'floor':'6F','catalog_only':True,'entry_route':'/core/#academy','assets':[],
                                 'commercial_execution':False})
        value = snapshot(data)
        value['assets'] = [a for a in value['assets'] if a['floor'] == '2F'
                           and a['tenant_id'] == 'community' and a['range_id'] == 'local']
        available_panels = panels(data, request.user.profile.role)
        value['assets'] = [device_metadata(a, available_panels) for a in value['assets']]
        network = network_observation(data['plan_id'])
        routers = {r.get('service'): r for r in (network or {}).get('routers', []) if isinstance(r, dict)}
        for a in value['assets']:
            if a['service'] in routers:
                a['network'] = routers[a['service']]
                a['description'] += ' ' + ROUTING_ROLES.get(a['service'], '')
        value['assets'] += network_assets(network)
        value['network_observation'] = {'fresh': network is not None, 'observed_at': network.get('observed_at') if network else None}
        ssh_username = settings.CONFIG.get('ssh_username')
        if not isinstance(ssh_username, str) or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', ssh_username):
            ssh_username = None
        value.update(schema_version='xoc.datacenter/0.1.0', tier='community',
                     panels=available_panels, racks=[dict(r, asset_ids=[a['asset_id'] for a in value['assets'] if a['rack_id']==r['id']]) for r in RACKS],
                     host_access={'host':settings.CONFIG['public_host'], 'username_hint':ssh_username, 'port':22},
                     floors=[dict(id=i,title=t,subtitle=s,minimum_tier=m,enabled=i in allowed,
                                  access_requirement={'6F':'community_bundle_and_purchased_catalog',
                                                      '7F':'institution_scenario_purchase',
                                                      '8F':'joint_force_virtual_company'}.get(i,'edition'),
                                  unavailable_reason=None if i in allowed else 'not_licensed') for i,t,s,m in FLOORS],
                     selected_floor=floor, allowed_floors=allowed,
                     preview_floors=[f[0] for f in FLOORS if f[0] not in ('2F',)+FACILITY_FLOORS] if request.user.profile.role=='admin' else [])
        if floor in FACILITY_FLOORS:
            catalog = facility_catalog()
            value.update(facility_view=True, simulator=False, assets=[], racks=[],
                         facilities=[f for f in catalog['facilities'] if f.get('floor') == floor],
                         facility_systems=catalog['systems'], facility_note=catalog.get('note', ''))
        return JsonResponse(value)
    except (OSError, ValueError, KeyError, TypeError):
        return JsonResponse({'error':'registry_unavailable'},status=503)


@require_GET
@protected('registry.read')
def design(request, floor):
    """Administrator-only architecture preview; never grants commercial access."""
    if request.user.profile.role != 'admin':
        return JsonResponse({'error':'permission_denied'},status=403)
    try:
        data=registry()
        if not any(c['id']=='noc' for c in data['components']):
            return JsonResponse({'error':'component_not_installed'},status=404)
        item=next((f for f in FLOORS if f[0]==floor and floor!='2F'),None)
        if item is None:
            return JsonResponse({'error':'not_found'},status=404)
        return JsonResponse({'schema_version':'xoc.datacenter-design/0.1.0',
                             'floor':{'id':item[0],'title':item[1]}, 'preview_only':True,
                             'assets':[], 'actions':[],
                             'workspace_design':floor in ('6F','7F')})
    except (OSError,ValueError,KeyError,TypeError):
        return JsonResponse({'error':'registry_unavailable'},status=503)
