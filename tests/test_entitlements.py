import base64
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import subprocess

import pytest
from xocrange.entitlements import verifier
from xocrange.errors import XocError
from xocrange.planner import plan
from test_planner import module

ROOT = Path(__file__).resolve().parents[1]
c7 = verifier(ROOT)
NOW = datetime(2026, 11, 8, 12, tzinfo=timezone.utc)
MANIFEST = {'id': 'M7', 'version': '1.2.0', 'commercial': True, 'minimum_tier': 'live-fire'}
IDENTITY = {'institution_id': 'school-one', 'range_id': 'range-one'}


@pytest.fixture
def issuer(tmp_path):
    private = tmp_path/'test-private.pem'; public = tmp_path/'test-public.pem'
    subprocess.run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(private)], check=True, capture_output=True)
    subprocess.run(['openssl', 'pkey', '-in', str(private), '-pubout', '-out', str(public)], check=True, capture_output=True)
    def sign(**changes):
        payload = dict(license_id='test-license', **IDENTITY, tier='live-fire', issued_at='2020-01-01T00:00:00Z',
                       not_before='2020-01-01T00:00:00Z', expires_at='2099-01-01T00:00:00Z', core='>=0.1.0 <0.2.0',
                       modules={'M7': '>=1.0.0 <2.0.0'}, content={'content-one': '=1.0.0'}, scenarios={'scenario-one': '=2.0.0'})
        payload.update(changes)
        envelope = {'schema_version': 'xoc.entitlement/0.1.0', 'key_id': 'ephemeral-test', 'payload': payload}
        message = tmp_path/'message'; message.write_bytes(c7.canonical(envelope))
        signed = subprocess.run(['openssl', 'pkeyutl', '-sign', '-inkey', str(private), '-rawin', '-in', str(message)], check=True, capture_output=True)
        envelope['signature'] = base64.b64encode(signed.stdout).decode()
        return envelope
    return sign, {'ephemeral-test': public.read_text()}


def verified(issuer, **changes):
    sign, keys = issuer
    return c7.verify(sign(**changes), keys, IDENTITY, '0.1.0', NOW)


def test_keyless_community_and_stop_even_with_unavailable_paid_license():
    assert c7.authorize(None, dict(MANIFEST, id='platform', commercial=False, minimum_tier='community'), 'start')['mode'] == 'community'
    from xocrange.entitlements import authorize
    assert authorize(ROOT, MANIFEST, 'stop')['mode'] == 'stop'
    with pytest.raises(c7.Denied, match='commercial_unavailable'):
        c7.authorize(None, MANIFEST, 'start')


def test_host_verifier_does_not_write_into_platform_build_context(checkout):
    import sys
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = False
        verifier(checkout)
        assert not (checkout/'components/platform/control/__pycache__').exists()
        assert plan(checkout)['lock']['selected'] == ['platform']
    finally:
        sys.dont_write_bytecode = previous


def test_real_ed25519_module_and_purchase_grants(issuer):
    grant = verified(issuer)
    assert c7.authorize(grant, MANIFEST, 'start')['mode'] == 'licensed'
    assert c7.authorize(grant, MANIFEST, 'execute', resource='content-one', resource_version='1.0.0', category='content')
    assert c7.authorize(grant, MANIFEST, 'execute', resource='scenario-one', resource_version='2.0.0', category='scenarios')
    for resource, version, category in [('unbought','1.0.0','content'),('content-one','2.0.0','content'),('content-one','1.0.0','scenarios')]:
        with pytest.raises(c7.Denied, match='entitlement_purchase'):
            c7.authorize(grant, MANIFEST, 'execute', resource=resource, resource_version=version, category=category)


def test_tampering_unknown_key_and_duplicate_json_rejected(issuer):
    sign, keys = issuer
    envelope = sign(); envelope['payload']['tier'] = 'joint-force'
    with pytest.raises(c7.Denied, match='entitlement_signature'):
        c7.verify(envelope, keys, IDENTITY, '0.1.0', NOW)
    with pytest.raises(c7.Denied, match='entitlement_untrusted_key'):
        c7.verify(sign(), {}, IDENTITY, '0.1.0', NOW)
    with pytest.raises(c7.Denied):
        c7.document(b'{"tier":"community","tier":"joint-force"}')


@pytest.mark.parametrize('changes,code', [
    ({'institution_id':'school-two'}, 'entitlement_institution'),
    ({'range_id':'range-two'}, 'entitlement_institution'),
    ({'core':'>=0.2.0'}, 'entitlement_core_version'),
    ({'core':'*'}, 'entitlement_version'),
    ({'not_before':'2026-12-01T00:00:00Z'}, 'entitlement_not_yet_valid'),
    ({'issued_at':'2026-11-09T00:00:00Z'}, 'entitlement_not_yet_valid'),
    ({'tier':'community'}, 'entitlement_tier'),
    ({'modules':{'M7':'*'}}, 'entitlement_version'),
    ({'modules':{'../../key':'1.0.0'}}, 'entitlement_format'),
    ({'expires_at':'2027-01-01'}, 'entitlement_time'),
    ({'surprise':True}, 'entitlement_format'),
])
def test_signed_but_invalid_claims_are_rejected(issuer, changes, code):
    with pytest.raises(c7.Denied, match=code):
        verified(issuer, **changes)


def test_expiry_exact_boundary_keeps_read_export_stop_only(issuer):
    grant = verified(issuer, expires_at='2026-11-08T12:00:00Z')
    for action in ('read', 'export', 'stop'):
        assert c7.authorize(grant, MANIFEST, action)['mode'] == 'read-only'
    for action in ('install', 'register', 'start', 'execute'):
        with pytest.raises(c7.Denied, match='entitlement_expired'):
            c7.authorize(grant, MANIFEST, action)


def test_tier_and_module_version_must_both_match(issuer):
    with pytest.raises(c7.Denied, match='entitlement_tier'):
        c7.authorize(verified(issuer), dict(MANIFEST, minimum_tier='joint-force'), 'start')
    with pytest.raises(c7.Denied, match='entitlement_module'):
        c7.authorize(verified(issuer), dict(MANIFEST, version='2.0.0'), 'start')
    with pytest.raises(c7.Denied, match='entitlement_module'):
        c7.authorize(verified(issuer), dict(MANIFEST, id='M8'), 'start')


def test_planner_rechecks_license_without_persisting_grant_in_lock(checkout, issuer, tmp_path):
    sign, keys = issuer
    module(checkout, 'M7', commercial=True, minimum_tier='live-fire', version='1.2.0')
    directory = tmp_path/'entitlement'; (directory/'trust').mkdir(parents=True)
    (directory/'trust/ephemeral-test.pem').write_text(keys['ephemeral-test'])
    (directory/'identity.json').write_text(json.dumps(IDENTITY))
    (directory/'license.json').write_text(json.dumps(sign()))
    result = plan(checkout, include=['M7'], entitlement_dir=directory)
    assert 'M7' in result['lock']['selected']
    assert 'signature' not in json.dumps(result['lock'])
    (directory/'license.json').write_text(json.dumps(sign(expires_at='2026-01-02T00:00:00Z')))
    with pytest.raises(XocError, match='does not permit') as exc:
        plan(checkout, include=['M7'], entitlement_dir=directory)
    assert exc.value.code == 'entitlement_expired'
    assert plan(checkout, include=['M7'], entitlement_dir=directory, entitlement_action='read')['lock'] == result['lock']


def test_trust_key_cannot_be_redirected(issuer, tmp_path):
    sign, keys = issuer
    (tmp_path/'license.json').write_text(json.dumps(sign()))
    (tmp_path/'trust').mkdir()
    (tmp_path/'key.pem').write_text(keys['ephemeral-test'])
    (tmp_path/'trust/ephemeral-test.pem').symlink_to(tmp_path/'key.pem')
    with pytest.raises(c7.Denied, match='entitlement_path'):
        c7.load(tmp_path, '0.1.0', NOW)


def test_collection_identity_follows_the_verified_grant(issuer, tmp_path):
    """ADR-0008 §7: C1 tenant/range come from a verified grant, else the Community identity."""
    from xocrange.entitlements import collection_identity
    from xocrange.event_store import Store
    sign, keys = issuer
    directory = tmp_path/'entitlement'
    assert collection_identity(ROOT, directory) == ('community', 'local')
    (directory/'trust').mkdir(parents=True)
    (directory/'trust/ephemeral-test.pem').write_text(keys['ephemeral-test'])
    (directory/'identity.json').write_text(json.dumps(IDENTITY))
    (directory/'license.json').write_text(json.dumps(sign()))
    assert collection_identity(ROOT, directory) == ('school-one', 'range-one')
    tampered = sign(); tampered['payload']['range_id'] = 'range-two'
    (directory/'license.json').write_text(json.dumps(tampered))
    assert collection_identity(ROOT, directory) == ('community', 'local')
    store = Store(tmp_path/'store', identity=('school-one', 'range-one'))
    line = json.dumps({'timestamp': '2026-11-14T00:00:00.000000+0000', 'event_type': 'alert', 'src_ip': '10.20.30.9', 'src_port': 1,
                       'dest_ip': '10.20.32.80', 'dest_port': 80, 'proto': 'TCP', 'alert': {'signature_id': 1, 'severity': 2, 'action': 'allowed', 'signature': 'x'}}).encode()
    store.ingest('suricata', 'ips-eve', 1, line, observed='2026-11-14T00:00:01Z')
    event = json.loads(store.db.execute('SELECT event FROM events').fetchone()[0])
    assert (event['tenant_id'], event['range_id']) == ('school-one', 'range-one')


def _grant_dir(tmp_path, sign, keys):
    directory = tmp_path/'entitlement'; (directory/'trust').mkdir(parents=True)
    (directory/'trust/ephemeral-test.pem').write_text(keys['ephemeral-test'])
    (directory/'identity.json').write_text(json.dumps(IDENTITY))
    (directory/'license.json').write_text(json.dumps(sign()))
    return directory


def test_evidence_volumes_only_for_the_entitled_module(checkout, issuer, tmp_path):
    """ADR-0008 §3/§4: the evidence socket and credentials reach only the declaring commercial module."""
    sign, keys = issuer
    directory = _grant_dir(tmp_path, sign, keys)
    import shutil
    shutil.copytree(ROOT/'components', checkout/'components', dirs_exist_ok=True)
    module(checkout, 'M7', commercial=True, minimum_tier='live-fire', version='1.2.0',
           requires={'components': ['siem'], 'capabilities': ['evidence-query']})
    compose = plan(checkout, include=['M7'], entitlement_dir=directory, allow_experimental=True)['compose']
    assert compose['services']['m7']['volumes'] == ['evidence-M7:/run/xoc-evidence:ro', 'module-M7-credentials:/run/xoc-module:ro']
    assert {'evidence-M7', 'module-M7-credentials'} <= set(compose['volumes'])
    others = [n for n, s in compose['services'].items() if n != 'm7' and any('evidence-M7' in v or 'module-M7' in v for v in s.get('volumes', []))]
    assert others == []


def test_evidence_query_is_refused_to_community_modules(checkout):
    import shutil
    shutil.copytree(ROOT/'components', checkout/'components', dirs_exist_ok=True)
    module(checkout, 'free-ext', requires={'components': ['siem'], 'capabilities': ['evidence-query']})
    with pytest.raises(XocError) as exc:
        plan(checkout, include=['free-ext'], allow_experimental=True)
    assert exc.value.code == 'capability_not_permitted'


def _keypair(tmp_path, name):
    private = tmp_path/f'{name}-private.pem'; public = tmp_path/f'{name}-public.pem'
    subprocess.run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(private)], check=True, capture_output=True)
    subprocess.run(['openssl', 'pkey', '-in', str(private), '-pubout', '-out', str(public)], check=True, capture_output=True)
    return private, public.read_text()


def _signed(tmp_path, private, envelope):
    message = tmp_path/'message'
    message.write_bytes(c7.canonical({k: envelope[k] for k in ('schema_version', 'key_id', 'payload')}))
    out = subprocess.run(['openssl', 'pkeyutl', '-sign', '-inkey', str(private), '-rawin', '-in', str(message)], check=True, capture_output=True)
    return dict(envelope, signature=base64.b64encode(out.stdout).decode())


@pytest.fixture
def delegation(tmp_path):
    """ADR 0011 §7: vendor -> Range Control issuer certificate -> range license with a domain."""
    vendor, vendor_public = _keypair(tmp_path, 'vendor')
    rc, rc_public = _keypair(tmp_path, 'rc')
    def issuer(**changes):
        payload = dict(issuer_id='rc-school-one', public_key=rc_public, institution_id='school-one', tier='live-fire', seats=30,
                       modules={'M7': '>=1.0.0 <2.0.0'}, content={}, scenarios={}, issued_at='2020-01-01T00:00:00Z',
                       not_before='2020-01-01T00:00:00Z', expires_at='2099-01-01T00:00:00Z')
        payload.update(changes)
        return _signed(tmp_path, vendor, {'schema_version': 'xoc.issuer/0.1.0', 'key_id': 'vendor-2026', 'payload': payload})
    def license(cert=None, key=rc, key_id='rc-school-one', **changes):
        payload = dict(license_id='lic-alice', **IDENTITY, tier='live-fire', issued_at='2020-01-01T00:00:00Z',
                       not_before='2020-01-01T00:00:00Z', expires_at='2098-01-01T00:00:00Z', core='>=0.1.0 <0.2.0',
                       modules={'M7': '>=1.0.0 <2.0.0'}, content={}, scenarios={}, domain='alice.lab')
        payload.update(changes)
        envelope = {'schema_version': 'xoc.entitlement/0.2.0', 'key_id': key_id, 'payload': payload, 'issuer': cert or issuer()}
        signed = _signed(tmp_path, key, envelope)
        return signed
    return issuer, license, {'vendor-2026': vendor_public}, vendor


def test_delegated_license_carries_the_learner_domain(delegation):
    issuer, license, keys, _ = delegation
    grant = c7.verify(license(), keys, IDENTITY, '0.1.0', NOW)
    assert grant['domain'] == 'alice.lab' and grant['issuer_id'] == 'rc-school-one' and not grant['expired']
    assert c7.authorize(grant, MANIFEST, 'start')['mode'] == 'licensed'
    assert c7.trust_key_id(license()) == 'vendor-2026'


@pytest.mark.parametrize('changes,code', [
    ({'tier': 'joint-force'}, 'entitlement_issuer'),                                   # above the issuer's tier
    ({'modules': {'M7': '>=1.0.0 <2.0.0', 'M9': '>=1.0.0'}}, 'entitlement_issuer'),   # a module the vendor did not grant
    ({'expires_at': '2099-06-01T00:00:00Z'}, 'entitlement_issuer'),                   # beyond the issuer's validity
    ({'domain': 'www.naver.com'}, 'entitlement_domain'),
    ({'domain': 'lab'}, 'entitlement_domain'),
    ({'domain': 'Alice.lab'}, 'entitlement_domain'),
    ({'domain': 'xoc.range'}, 'entitlement_domain'),
    ({'domain': 'a..lab'}, 'entitlement_domain'),
])
def test_delegated_license_stays_inside_the_issuer_grant(delegation, changes, code):
    _, license, keys, _ = delegation
    with pytest.raises(c7.Denied, match=code):
        c7.verify(license(**changes), keys, IDENTITY, '0.1.0', NOW)


def test_issuer_chain_must_be_rooted_in_a_trusted_vendor_key(delegation, tmp_path):
    issuer, license, keys, vendor = delegation
    with pytest.raises(c7.Denied, match='entitlement_untrusted_key'):
        c7.verify(license(), {}, IDENTITY, '0.1.0', NOW)
    other, _ = _keypair(tmp_path, 'other')
    with pytest.raises(c7.Denied, match='entitlement_signature'):              # not signed by the issuer's key
        c7.verify(license(key=other), keys, IDENTITY, '0.1.0', NOW)
    with pytest.raises(c7.Denied, match='entitlement_issuer'):                 # key id is not the issuer's
        c7.verify(license(key_id='someone-else'), keys, IDENTITY, '0.1.0', NOW)
    with pytest.raises(c7.Denied, match='entitlement_issuer'):                 # issuer for another institution
        c7.verify(license(cert=issuer(institution_id='school-two')), keys, IDENTITY, '0.1.0', NOW)
    forged = issuer(); forged['payload'] = dict(forged['payload'], seats=9999)
    with pytest.raises(c7.Denied, match='entitlement_signature'):              # tampered issuer certificate
        c7.verify(license(cert=forged), keys, IDENTITY, '0.1.0', NOW)
    for good in ('bob.class1.internal', 'x.home.arpa', 'team-7.test'):
        assert c7.domain(good) == good


def test_learner_domain_follows_the_license_with_a_grace_period(monkeypatch):
    from datetime import timedelta
    import xocrange.entitlements as host
    base = {'domain': 'alice.lab', 'expired': False, 'expires_at': '2026-11-01T00:00:00Z'}
    monkeypatch.setattr(host, 'grant', lambda root, directory=None: dict(base))
    assert host.learner_domain(ROOT) == 'alice.lab'
    monkeypatch.setattr(host, 'grant', lambda root, directory=None: dict(base, expired=True))
    assert host.learner_domain(ROOT, now=NOW.replace(month=11, day=10)) == 'alice.lab'      # within 14 days
    assert host.learner_domain(ROOT, now=NOW.replace(month=11, day=20)) is None             # after the grace period
    monkeypatch.setattr(host, 'grant', lambda root, directory=None: None)
    assert host.learner_domain(ROOT) is None                                                 # Community
    def broken(root, directory=None):
        raise XocError('entitlement_signature', 'bad')
    monkeypatch.setattr(host, 'grant', broken)
    assert host.learner_domain(ROOT) is None
