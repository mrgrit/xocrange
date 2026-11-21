"""ADR 0014: facility state from the M4 module, checked by Core; requests handed back as files."""
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import pytest
from jsonschema import Draft7Validator

from test_platform_security import application, app, login, send
from test_entitlements import issuer, IDENTITY
from test_registry import registry_files
from conftest import checkout

ROOT = Path(__file__).resolve().parents[1]
STATE = Draft7Validator(json.loads((ROOT/'src/xocrange/contracts/facility-state.json').read_text()))
REQUEST = Draft7Validator(json.loads((ROOT/'src/xocrange/contracts/facility-request.json').read_text()))
MODULE = {'id': 'm4-facility', 'title': 'Facility simulator and fault injection', 'version': '0.1.0', 'commercial': True,
          'minimum_tier': 'live-fire', 'provides': ['facility-simulator'], 'requires': {'components': [], 'capabilities': ['facility-state']}}


def stamp(delta=0):
    return (datetime.now(timezone.utc) + timedelta(seconds=delta)).strftime('%Y-%m-%dT%H:%M:%SZ')


def sample():
    return {'schema_version': 'xoc.facility-state/0.1.0', 'generated_at': stamp(), 'sequence': 7, 'time_scale': 1.0, 'load_source': 'profile',
            'summary': [{'key': 'it_load_kw', 'label': 'IT 부하', 'value': 31.4, 'unit': 'kW'}, {'key': 'power_source', 'label': '전원', 'value': '수전', 'unit': ''},
                        {'key': 'on_battery', 'label': '배터리 운전', 'value': False, 'unit': ''}],
            'assets': [{'id': 'chiller-01', 'status': 'normal', 'metrics': [{'key': 'capacity_kw', 'label': '냉방 용량', 'value': 55, 'unit': 'kW'}]},
                       {'id': 'ups-01', 'status': 'warning', 'metrics': []}],
            'aisles': [{'id': 'A', 'floor': '2F', 'temp_c': 22.4, 'status': 'normal'}],
            'alarms': [{'id': 'aisle_temp_high.A', 'level': 'warning', 'asset_id': None, 'message': 'A 통로 온도 상승', 'since': stamp(-60)}],
            'faults': [{'handle': 'a'*32, 'fault': 'crac_fail', 'title': '항온항습기 정지', 'target': 'crac-01', 'started_at': stamp(-60),
                        'expires_at': stamp(540), 'requested_by': 'admin'}],
            'catalog': {'faults': [{'id': 'crac_fail', 'title': '항온항습기 정지', 'system': 'cooling', 'default_minutes': 10,
                                    'targets': [{'id': 'crac-01', 'title': '항온항습기 1'}, {'id': '*', 'title': '전체'}]}],
                        'shed_groups': [{'id': 'batch', 'title': '배치 작업', 'impact': '학습 작업 중단', 'load_kw': 8.5, 'shed': False}]},
            'handled': [{'request_id': 'b'*32, 'status': 'applied', 'code': 'ok', 'at': stamp(-60)}],
            'events': [{'at': stamp(-60), 'kind': 'inject', 'message': '장애 주입: 항온항습기 정지 (crac-01)'}]}


def edit(path, value):
    def change(document):
        node = document
        for key in path[:-1]:
            node = node[key]
        if value is KeyError:
            del node[path[-1]]
        else:
            node[path[-1]] = value
    return change


BROKEN = [edit(['schema_version'], 'xoc.facility-state/9'), edit(['sequence'], -1), edit(['sequence'], True), edit(['time_scale'], 500),
          edit(['load_source'], 'docker'), edit(['generated_at'], '2026-11-20 10:00:00'), edit(['extra'], 1), edit(['events'], KeyError),
          edit(['assets', 0, 'id'], 'Chiller 01'), edit(['assets', 0, 'status'], 'ok'), edit(['assets', 0, 'metrics', 0, 'label'], '<b>x</b>'),
          edit(['assets', 0, 'metrics', 0, 'value'], float('inf')), edit(['assets', 0, 'metrics', 0, 'value'], None),
          edit(['assets', 0, 'metrics', 0, 'key'], 'Capacity'), edit(['assets', 0, 'answer'], '정답'),
          edit(['assets', 0, 'title'], '<i>냉동기</i>'), edit(['assets', 0, 'title'], ''), edit(['assets', 0, 'title'], 'x'*61),
          edit(['aisles', 0, 'floor'], '10F'), edit(['aisles', 0, 'temp_c'], '22'), edit(['alarms', 0, 'level'], 'info'),
          edit(['alarms', 0, 'message'], 'x'*201), edit(['alarms', 0, 'asset_id'], 5), edit(['faults', 0, 'handle'], 'abc'),
          edit(['faults', 0, 'target'], '../etc'), edit(['faults', 0, 'requested_by'], 'a\nb'), edit(['catalog', 'faults', 0, 'system'], 'it'),
          edit(['catalog', 'faults', 0, 'default_minutes'], 0), edit(['catalog', 'faults', 0, 'targets', 0, 'title'], ''),
          edit(['catalog', 'shed_groups', 0, 'shed'], 'no'), edit(['catalog', 'hints'], []), edit(['handled', 0, 'status'], 'done'),
          edit(['events', 0, 'kind'], 'grade'), edit(['events', 0, 'message'], 'a<script>'),
          edit(['summary'], [{'key': 'k', 'label': 'l', 'value': 1, 'unit': ''}]*25)]


def test_platform_check_and_contract_agree(application):
    from control.facility import checked
    document = sample()
    assert not list(STATE.iter_errors(document))
    assert checked(document)['assets'][0]['id'] == 'chiller-01' and 'title' not in checked(document)['assets'][0]
    named = copy.deepcopy(document); named['assets'][0]['title'] = '수랭식 냉동기'   # the name is optional
    assert not list(STATE.iter_errors(named)) and checked(named)['assets'][0]['title'] == '수랭식 냉동기'
    for change in BROKEN:
        broken = copy.deepcopy(document); change(broken)
        assert list(STATE.iter_errors(broken)), broken
        with pytest.raises((ValueError, KeyError, TypeError)):
            checked(broken)


@pytest.fixture
def facility(app, registry_files, issuer, tmp_path, monkeypatch):
    from django.conf import settings
    data, files, _ = registry_files; sign, keys = issuer
    directory = tmp_path/'license'; (directory/'trust').mkdir(parents=True)
    (directory/'identity.json').write_text(json.dumps(IDENTITY))
    (directory/'trust/ephemeral-test.pem').write_text(keys['ephemeral-test'])
    token = directory/'license.json'
    monkeypatch.setattr(settings, 'ENTITLEMENT_DIR', str(directory), raising=False)
    state, requests = tmp_path/'state', tmp_path/'requests'
    state.mkdir(); requests.mkdir()
    monkeypatch.setattr(settings, 'FACILITY_STATE_DIR', str(state), raising=False)
    monkeypatch.setattr(settings, 'FACILITY_REQUEST_DIR', str(requests), raising=False)
    def install(licensed=True, **changes):
        data['components'] = [c for c in data['components'] if c['id'] != MODULE['id']] + [MODULE]
        files['REGISTRY_FILE'].write_text(json.dumps(data))
        if licensed:
            token.write_text(json.dumps(sign(modules={'m4-facility': '>=0.1.0 <0.2.0'}, **changes)))
    return install, state, requests


def test_without_the_module_the_datacenter_shows_baseline_only(app, facility):
    login(app)
    assert app.get('/core/api/facility').json() == {'installed': False, 'simulator': False, 'reason': 'not_installed', 'can_operate': False,
                                                    'can_instruct': False}
    floor = app.get('/core/api/datacenter/floors/B1').json()
    assert floor['simulator'] is False and floor['facility_live']['installed'] is False
    assert send(app, 'facility/requests', {'action': 'clear_all'}).status_code == 404


def test_unlicensed_or_silent_module_is_never_shown_as_a_simulator(app, facility):
    install, state, _ = facility; login(app)
    install(licensed=False)
    assert app.get('/core/api/facility').json()['reason'] == 'commercial_unavailable'
    install()
    assert app.get('/core/api/facility').json() == {'installed': True, 'simulator': False, 'reason': 'absent', 'read_only': False,
                                                    'module': {'id': 'm4-facility', 'version': '0.1.0'}, 'can_operate': False,
                                                    'can_instruct': False}
    old = sample(); old['generated_at'] = stamp(-120); (state/'state.json').write_text(json.dumps(old))
    value = app.get('/core/api/facility').json()
    assert value['simulator'] is False and value['reason'] == 'stale' and value['can_operate'] is False
    assert send(app, 'facility/requests', {'action': 'clear_all'}).status_code == 503
    bad = sample(); bad['events'][0]['message'] = '<img src=x>'; (state/'state.json').write_text(json.dumps(bad))
    value = app.get('/core/api/facility').json()
    assert value['reason'] == 'invalid' and 'state' not in value
    (state/'state.json').write_text('{"schema_version":' + '[' * 200000)
    assert app.get('/core/api/facility').json()['reason'] == 'invalid'


def test_live_state_reaches_the_screen_and_requests_become_files(app, facility):
    from control.models import Audit
    install, state, requests = facility; install(); login(app)
    (state/'state.json').write_text(json.dumps(sample()))
    value = app.get('/core/api/facility').json()
    assert value['simulator'] is True and value['can_operate'] is True and value['can_instruct'] is True and value['state']['faults'][0]['target'] == 'crac-01'
    floor = app.get('/core/api/datacenter/floors/B1').json()
    assert floor['simulator'] is True and floor['facility_live']['state']['assets'][0]['id'] == 'chiller-01'
    response = send(app, 'facility/requests', {'action': 'inject', 'fault': 'crac_fail', 'target': 'crac-01', 'minutes': 10})
    assert response.status_code == 202
    written = json.loads((requests/(response.json()['request_id'] + '.json')).read_text())
    assert not list(REQUEST.iter_errors(written))
    assert written['requested_by'] == 'admin' and written['fault'] == 'crac_fail' and written['minutes'] == 10
    assert (requests/(response.json()['request_id'] + '.json')).stat().st_mode & 0o777 == 0o644
    record = Audit.objects.filter(action='facility_inject').get()
    assert record.outcome == 'requested' and record.target == 'crac_fail' and record.after['request_id'] == written['request_id']
    for body in ({'action': 'clear', 'handle': 'a'*32}, {'action': 'clear_all'}, {'action': 'shed', 'group': 'batch'},
                 {'action': 'restore', 'group': 'batch'}, {'action': 'time_scale', 'value': 30}):
        answer = send(app, 'facility/requests', body)
        assert answer.status_code == 202
        assert not list(REQUEST.iter_errors(json.loads((requests/(answer.json()['request_id'] + '.json')).read_text())))
    for body in ({'action': 'inject', 'fault': 'crac_fail', 'target': 'crac-01'}, {'action': 'inject', 'fault': 'crac_fail', 'target': 'crac-01', 'minutes': 500},
                 {'action': 'inject', 'fault': 'crac_fail', 'target': 'crac-01', 'minutes': True}, {'action': 'inject', 'fault': '../x', 'target': '*', 'minutes': 5},
                 {'action': 'clear_all', 'handle': 'a'*32}, {'action': 'reboot'}, {'action': 'time_scale', 'value': 1000},
                 {'action': 'shed', 'group': 'batch', 'requested_by': 'root'}, {}):
        assert send(app, 'facility/requests', body).status_code == 400, body
    assert len(list(requests.glob('*.json'))) == 6 and not list(requests.glob('.*'))


def test_answered_requests_are_removed_and_a_backlog_is_refused(app, facility):
    install, state, requests = facility; install(); login(app)
    document = sample(); (state/'state.json').write_text(json.dumps(document))
    first = send(app, 'facility/requests', {'action': 'clear_all'}).json()['request_id']
    document['handled'] = [{'request_id': first, 'status': 'applied', 'code': 'ok', 'at': stamp()}]
    (state/'state.json').write_text(json.dumps(document))
    second = send(app, 'facility/requests', {'action': 'clear_all'}).json()['request_id']
    assert [p.stem for p in requests.glob('*.json')] == [second]
    (requests/'notes.txt').write_text('kept')
    for index in range(70):
        (requests/(f'{index:032x}.json')).write_text('{}')
    assert send(app, 'facility/requests', {'action': 'clear_all'}).status_code == 429
    assert (requests/'notes.txt').exists()


def test_viewers_read_but_do_not_operate_and_an_expired_license_is_read_only(app, facility):
    install, state, requests = facility; install()
    (state/'state.json').write_text(json.dumps(sample()))
    login(app, 'viewer')
    assert app.get('/core/api/facility').json()['can_operate'] is False
    assert send(app, 'facility/requests', {'action': 'clear_all'}).status_code == 403
    send(app, 'logout', {}); login(app, 'operator')
    assert app.get('/core/api/facility').json()['can_operate'] is True
    install(expires_at='2021-01-01T00:00:00Z')
    value = app.get('/core/api/facility').json()
    assert value['simulator'] is True and value['read_only'] is True and value['can_operate'] is False and value['can_instruct'] is False
    assert send(app, 'facility/requests', {'action': 'time_scale', 'value': 3}).json() == {'error': 'entitlement_expired'}
    assert not list(requests.glob('*.json'))


def test_only_instructors_inject_or_undo_faults(app, facility):
    """Students (operators) keep operations, trainings, shedding and time scale; injecting and undoing
    faults is an instructor (administrator) tool. A refused request is audited and writes no file."""
    from control.models import Audit
    install, state, requests = facility; install()
    (state/'state.json').write_text(json.dumps(sample()))
    login(app, 'operator')
    value = app.get('/core/api/facility').json()
    assert value['can_operate'] is True and value['can_instruct'] is False
    for body in ({'action': 'inject', 'fault': 'crac_fail', 'target': 'crac-01', 'minutes': 10},
                 {'action': 'clear', 'handle': 'a'*32}, {'action': 'clear_all'}):
        answer = send(app, 'facility/requests', body)
        assert answer.status_code == 403 and answer.json() == {'error': 'permission_denied'}, body
    assert not list(requests.glob('*.json'))
    assert sorted(Audit.objects.filter(outcome='denied', action__startswith='facility_').values_list('action', flat=True)) == \
        ['facility_clear', 'facility_clear_all', 'facility_inject']
    for body in ({'action': 'operate', 'op': 'replace_filter', 'target': 'crac-01'}, {'action': 'time_scale', 'value': 10},
                 {'action': 'drill_start', 'drill': 'fac01a'}, {'action': 'drill_stop'},
                 {'action': 'shed', 'group': 'batch'}, {'action': 'restore', 'group': 'batch'}):
        assert send(app, 'facility/requests', body).status_code == 202, body
    send(app, 'logout', {}); login(app, 'admin')
    assert app.get('/core/api/facility').json()['can_instruct'] is True
    for body in ({'action': 'inject', 'fault': 'crac_fail', 'target': 'crac-01', 'minutes': 10},
                 {'action': 'clear', 'handle': 'a'*32}, {'action': 'clear_all'}):
        assert send(app, 'facility/requests', body).status_code == 202, body


def _licensed(tmp_path, issuer):
    from test_entitlements import _grant_dir
    sign, keys = issuer
    return _grant_dir(tmp_path, sign, keys)


def test_only_the_module_and_the_platform_share_the_facility_volumes(checkout, issuer, tmp_path):
    import shutil
    from xocrange.planner import plan
    from test_entitlements import module
    shutil.copytree(ROOT/'components', checkout/'components', dirs_exist_ok=True)
    module(checkout, 'M7', commercial=True, minimum_tier='live-fire', version='1.2.0',
           requires={'components': [], 'capabilities': ['facility-state']})
    result = plan(checkout, preset='security-path', include=['M7', 'noc'], entitlement_dir=_licensed(tmp_path, issuer), allow_experimental=True)
    compose = result['compose']
    assert compose['services']['m7']['volumes'] == ['facility-state:/run/xoc-facility', 'facility-requests:/run/xoc-facility-requests:ro',
                                                     'module-M7-credentials:/run/xoc-module:ro']   # class-wide faults come from Range Control
    assert {'facility-state:/run/xoc-facility:ro', 'facility-requests:/run/xoc-facility-requests'} <= set(compose['services']['platform']['volumes'])
    others = [n for n, s in compose['services'].items() if n not in ('m7', 'platform') and any('facility-' in str(v) for v in s.get('volumes', []))]
    assert others == [] and {'facility-state', 'facility-requests'} <= set(compose['volumes'])
    plain = plan(checkout, preset='security-path', include=['noc'], allow_experimental=True)['compose']
    assert not any('facility-' in str(v) for s in plain['services'].values() for v in s.get('volumes', []))
    assert 'facility-state' not in plain.get('volumes', {})


def test_the_facility_capability_is_refused_to_community_modules_and_without_the_screen(checkout, issuer, tmp_path):
    import shutil
    from xocrange.errors import XocError
    from xocrange.planner import plan
    from test_entitlements import module
    shutil.copytree(ROOT/'components', checkout/'components', dirs_exist_ok=True)
    module(checkout, 'free-ext', requires={'components': [], 'capabilities': ['facility-state']})
    with pytest.raises(XocError) as exc:
        plan(checkout, preset='security-path', include=['free-ext', 'noc'], allow_experimental=True)
    assert exc.value.code == 'capability_not_permitted'
    shutil.rmtree(checkout/'modules.d/free-ext')
    module(checkout, 'M7', commercial=True, minimum_tier='live-fire', version='1.2.0',
           requires={'components': [], 'capabilities': ['facility-state']})
    with pytest.raises(XocError) as exc:
        plan(checkout, include=['M7'], entitlement_dir=_licensed(tmp_path, issuer), allow_experimental=True)
    assert exc.value.code == 'missing_capability'


def operated():
    """The sample with the optional parts a module 0.2 sends: actions, drills, a drill and work in progress."""
    document = sample()
    document['catalog']['faults'].append({'id': 'gpu_ecc_dbe', 'title': 'GPU 메모리 정정 불가 오류', 'system': 'compute',
                                          'default_minutes': 30, 'targets': [{'id': 'gpu-03', 'title': 'GPU 노드 03'}]})
    document['catalog']['operations'] = [
        {'id': 'drain_node', 'title': '노드 작업 제외(drain)', 'system': 'compute', 'minutes': 0, 'needs_drain': False,
         'targets': [{'id': 'gpu-03', 'title': 'GPU 노드 03'}]},
        {'id': 'power_cap', 'title': 'GPU 전력 상한 설정', 'system': 'compute', 'minutes': 0, 'needs_drain': False,
         'targets': [{'id': 'cluster', 'title': 'GPU 클러스터 전체'}], 'value': {'min': 50, 'max': 100, 'unit': '%', 'default': 80}}]
    document['catalog']['drills'] = [{'id': 'ai05b', 'title': '학습 작업이 멈췄다', 'brief': '학습 작업이 중단됐다는 알림이 왔다.',
                                      'course': 'ai', 'level': 2, 'minutes': 40, 'time_scale': 10}]
    document['drill'] = {'id': 'ai05b', 'title': '학습 작업이 멈췄다', 'brief': '학습 작업이 중단됐다는 알림이 왔다.', 'status': 'running',
                         'started_at': stamp(-60), 'ended_at': None, 'elapsed_min': 10.0, 'minutes': 40, 'open_faults': 1}
    document['work'] = [{'op': 'replace_gpu', 'title': 'GPU 모듈 교체', 'target': 'gpu-03', 'target_title': 'GPU 노드 03', 'minutes_left': 12.5}]
    return document


OPERATED_BROKEN = [edit(['catalog', 'operations', 0, 'system'], 'it'), edit(['catalog', 'operations', 0, 'needs_drain'], 'no'),
                   edit(['catalog', 'operations', 1, 'value', 'max'], 500), edit(['catalog', 'operations', 0, 'answer'], 'x'),
                   edit(['catalog', 'drills', 0, 'level'], 9), edit(['catalog', 'drills', 0, 'brief'], '<b>'),
                   edit(['catalog', 'drills', 0, 'steps'], []), edit(['drill', 'status'], 'graded'), edit(['drill', 'faults'], []),
                   edit(['drill', 'open_faults'], -1), edit(['work', 0, 'target'], '../x'), edit(['work', 0, 'minutes_left'], -1)]


def test_operator_actions_drills_and_work_are_optional_parts_of_the_contract(application):
    from control.facility import checked
    document = operated()
    assert not list(STATE.iter_errors(document))
    value = checked(document)
    assert value['drill']['status'] == 'running' and value['work'][0]['op'] == 'replace_gpu'
    assert [o['id'] for o in value['catalog']['operations']] == ['drain_node', 'power_cap'] and value['catalog']['drills'][0]['course'] == 'ai'
    assert checked(sample())['drill'] is None and checked(sample())['work'] == []          # a 0.1 module still validates
    for change in OPERATED_BROKEN:
        broken = copy.deepcopy(document); change(broken)
        assert list(STATE.iter_errors(broken)), broken
        with pytest.raises((ValueError, KeyError, TypeError)):
            checked(broken)


def test_operate_and_drill_requests_become_files(app, facility):
    install, state, requests = facility; install(); login(app)
    (state/'state.json').write_text(json.dumps(operated()))
    for body in ({'action': 'operate', 'op': 'drain_node', 'target': 'gpu-03'},
                 {'action': 'operate', 'op': 'power_cap', 'target': 'cluster', 'value': 70},
                 {'action': 'drill_start', 'drill': 'ai05b'}, {'action': 'drill_stop'}):
        response = send(app, 'facility/requests', body)
        assert response.status_code == 202, body
        written = json.loads((requests/(response.json()['request_id'] + '.json')).read_text())
        assert not list(REQUEST.iter_errors(written)) and {k: written[k] for k in body} == body
    for body in ({'action': 'operate', 'op': 'drain_node'}, {'action': 'operate', 'op': 'Drain', 'target': 'gpu-03'},
                 {'action': 'drill_start'}, {'action': 'drill_stop', 'drill': 'ai05b'}, {'action': 'inject', 'fault': 'x', 'target': 'y', 'minutes': 5, 'value': 3}):
        assert send(app, 'facility/requests', body).status_code == 400, body
