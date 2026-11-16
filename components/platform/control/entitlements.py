"""C7 verifier shared by the host planner and the unprivileged management API.

Only public Ed25519 keys are accepted. No network, issuance, registry passwords,
implicit wildcards or grace period. Signed bytes use the canonical() format below.
"""
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

TIERS = {'community': 0, 'live-fire': 1, 'joint-force': 2}
ID = re.compile(r'(?:[a-z][a-z0-9-]{0,63}|M(?:[1-9]|1[0-9]))\Z')
READ_ACTIONS = {'read', 'export', 'stop'}
ACTIONS = READ_ACTIONS | {'install', 'start', 'register', 'execute'}


class Denied(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Denied('entitlement_duplicate_key')
        result[key] = value
    return result


def document(raw):
    if len(raw) > 65536:
        raise Denied('entitlement_size')
    try:
        return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise Denied('entitlement_format') from exc


def read(path):
    path = Path(path)
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise Denied('entitlement_path')
    with path.open('rb') as stream:
        return document(stream.read(65537))


def fields(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected.split()):
        raise Denied('entitlement_format')


def identifier(value):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise Denied('entitlement_format')
    return value


def version_range(expression, version):
    if not isinstance(expression, str) or not 1 <= len(expression) <= 120:
        raise Denied('entitlement_version')
    if not isinstance(version, str) or not re.fullmatch(r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)', version):
        raise Denied('entitlement_version')
    current = tuple(map(int, version.split('.')))
    result = True
    for term in expression.split():
        match = re.fullmatch(r'(>=|<=|>|<|=)?((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))', term)
        if not match:
            raise Denied('entitlement_version')
        wanted = tuple(map(int, match[2].split('.')))
        result &= {'=': current == wanted, '>=': current >= wanted, '<=': current <= wanted,
                   '>': current > wanted, '<': current < wanted}[match[1] or '=']
    if not expression.split():
        raise Denied('entitlement_version')
    return result


def timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', value):
        raise Denied('entitlement_time')
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise Denied('entitlement_time') from exc


SCHEMAS = ('xoc.entitlement/0.1.0', 'xoc.entitlement/0.2.0')
ISSUER_SCHEMA = 'xoc.issuer/0.1.0'
LICENSE_FIELDS = 'license_id institution_id range_id tier issued_at not_before expires_at core modules content scenarios'
ISSUER_FIELDS = 'issuer_id public_key institution_id tier seats modules content scenarios issued_at not_before expires_at'
# ADR 0011: a Live Fire learner domain is an internal lab name, never a public site.
DOMAIN_SUFFIXES = ('lab', 'test', 'internal', 'home.arpa')
LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')


def public_key(pem):
    """DER of an exact Ed25519 SubjectPublicKeyInfo; RSA/ECDSA/private keys are refused."""
    if not isinstance(pem, str) or len(pem) > 1024:
        raise Denied('entitlement_untrusted_key')
    match = re.fullmatch(r'-----BEGIN PUBLIC KEY-----\s+([A-Za-z0-9+/=\s]+)-----END PUBLIC KEY-----\s*', pem)
    try:
        der = base64.b64decode(''.join(match[1].split()), validate=True) if match else b''
    except ValueError as exc:
        raise Denied('entitlement_signature') from exc
    if len(der) != 44 or der[:12] != bytes.fromhex('302a300506032b6570032100'):
        raise Denied('entitlement_signature')
    return der


def signed_by(der, envelope):
    try:
        signature = base64.b64decode(envelope['signature'], validate=True)
        if len(signature) != 64:
            raise ValueError()
        signed = canonical({'schema_version': envelope['schema_version'], 'key_id': envelope['key_id'], 'payload': envelope['payload']})
        with tempfile.TemporaryDirectory(prefix='xoc-c7-') as directory:
            base = Path(directory)
            (base/'key.der').write_bytes(der); (base/'sig').write_bytes(signature); (base/'message').write_bytes(signed)
            result = subprocess.run(['openssl', 'pkeyutl', '-verify', '-pubin', '-keyform', 'DER', '-inkey', str(base/'key.der'),
                                     '-rawin', '-in', str(base/'message'), '-sigfile', str(base/'sig')],
                                    capture_output=True, timeout=5)
        if result.returncode:
            raise ValueError()
    except (OSError, TypeError, ValueError, subprocess.TimeoutExpired) as exc:
        raise Denied('entitlement_signature') from exc


def domain(value):
    """None, or an internal lab domain such as alice.lab (ADR 0011)."""
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 253 or value != value.lower():
        raise Denied('entitlement_domain')
    labels = value.split('.')
    if len(labels) < 2 or not all(LABEL.match(x) for x in labels) or value == 'xoc.range':
        raise Denied('entitlement_domain')
    if not any(value.endswith('.' + suffix) and value != suffix for suffix in DOMAIN_SUFFIXES):
        raise Denied('entitlement_domain')
    return value


def grants(payload):
    for name in ('modules', 'content', 'scenarios'):
        items = payload[name]
        if not isinstance(items, dict) or len(items) > 256:
            raise Denied('entitlement_format')
        for item, requirement in items.items():
            identifier(item); version_range(requirement, '0.0.0')


def trust_key_id(envelope):
    """The vendor key that roots this license: the issuer certificate's key, else the license's."""
    issuer = envelope.get('issuer') if isinstance(envelope, dict) else None
    return identifier((issuer if isinstance(issuer, dict) else envelope).get('key_id'))


def verify_issuer(issuer, keys):
    """A vendor-signed issuer certificate (ADR 0011 §7): Range Control may sign range licenses
    for one institution within a tier, grants, seats and validity."""
    fields(issuer, 'schema_version key_id payload signature')
    if issuer['schema_version'] != ISSUER_SCHEMA:
        raise Denied('entitlement_schema')
    signed_by(public_key(keys.get(identifier(issuer['key_id']))), issuer)
    value = issuer['payload']
    fields(value, ISSUER_FIELDS)
    identifier(value['issuer_id']); identifier(value['institution_id'])
    if value['tier'] not in TIERS or value['tier'] == 'community':
        raise Denied('entitlement_tier')
    if not isinstance(value['seats'], int) or isinstance(value['seats'], bool) or not 1 <= value['seats'] <= 100000:
        raise Denied('entitlement_format')
    grants(value)
    if not timestamp(value['issued_at']) <= timestamp(value['not_before']) < timestamp(value['expires_at']):
        raise Denied('entitlement_not_yet_valid')
    return value


def verify(envelope, keys, identity, core_version, now=None):
    if not isinstance(envelope, dict) or envelope.get('schema_version') not in SCHEMAS:
        raise Denied('entitlement_schema')
    delegated = envelope['schema_version'] == 'xoc.entitlement/0.2.0' and 'issuer' in envelope
    fields(envelope, 'schema_version key_id payload signature' + (' issuer' if delegated else ''))
    key_id = identifier(envelope['key_id'])
    issuer = verify_issuer(envelope['issuer'], keys) if delegated else None
    if issuer is not None and key_id != issuer['issuer_id']:
        raise Denied('entitlement_issuer')
    signed_by(public_key(issuer['public_key'] if issuer else keys.get(key_id)), envelope)
    payload = envelope['payload']
    fields(payload, LICENSE_FIELDS + (' domain' if envelope['schema_version'] == 'xoc.entitlement/0.2.0' else ''))
    fields(identity, 'institution_id range_id')
    for name in ('license_id', 'institution_id', 'range_id'):
        identifier(payload[name])
    if any(payload[k] != identifier(identity[k]) for k in identity):
        raise Denied('entitlement_institution')
    if not isinstance(payload['tier'], str) or payload['tier'] not in TIERS or payload['tier'] == 'community':
        raise Denied('entitlement_tier')
    issued, begins, expires = (timestamp(payload[k]) for k in ('issued_at', 'not_before', 'expires_at'))
    clock = now or datetime.now(timezone.utc)
    if not issued <= begins < expires or clock < begins or clock < issued:
        raise Denied('entitlement_not_yet_valid')
    if not version_range(payload['core'], core_version):
        raise Denied('entitlement_core_version')
    grants(payload)
    domain(payload.get('domain'))
    if issuer is not None:
        # The issuer may only hand out what the vendor granted it, inside its own validity.
        if payload['institution_id'] != issuer['institution_id'] or TIERS[payload['tier']] > TIERS[issuer['tier']]:
            raise Denied('entitlement_issuer')
        for name in ('modules', 'content', 'scenarios'):
            if any(issuer[name].get(item) != requirement for item, requirement in payload[name].items()):
                raise Denied('entitlement_issuer')
        if begins < timestamp(issuer['not_before']) or expires > timestamp(issuer['expires_at']):
            raise Denied('entitlement_issuer')
    result = dict(payload, expired=clock >= expires, fingerprint=hashlib.sha256(canonical(envelope)).hexdigest())
    if issuer is not None:
        result['issuer_id'] = issuer['issuer_id']
    return result


def paid(manifest):
    return manifest.get('commercial', False) or manifest.get('minimum_tier', 'community') != 'community' or bool(re.fullmatch(r'M(?:[1-9]|1[0-9])', manifest['id']))


def authorize(grant, manifest, action, *, resource=None, resource_version=None, category=None):
    if action not in ACTIONS:
        raise Denied('entitlement_action')
    if not paid(manifest) and resource is None:
        return {'tier': 'community', 'mode': 'community'}
    if grant is None:
        raise Denied('commercial_unavailable')
    if TIERS[grant['tier']] < TIERS[manifest['minimum_tier']]:
        raise Denied('entitlement_tier')
    if manifest['id'] not in grant['modules'] or not version_range(grant['modules'][manifest['id']], manifest['version']):
        raise Denied('entitlement_module')
    if grant['expired'] and action not in READ_ACTIONS:
        raise Denied('entitlement_expired')
    if resource is not None:
        if category not in ('content', 'scenarios') or resource not in grant[category] or not version_range(grant[category][resource], resource_version):
            raise Denied('entitlement_purchase')
    return {'tier': grant['tier'], 'mode': 'read-only' if grant['expired'] else 'licensed', 'expires_at': grant['expires_at']}


def load(directory, core_version, now=None):
    base = Path(directory)
    if not (base/'license.json').exists():
        return None
    envelope = read(base/'license.json')
    key_id = trust_key_id(envelope)
    path = base/'trust'/(key_id+'.pem')
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise Denied('entitlement_path')
    try:
        with path.open('r') as stream:
            pem = stream.read(1025)
    except OSError as exc:
        raise Denied('entitlement_untrusted_key') from exc
    return verify(envelope, {key_id: pem}, read(base/'identity.json'), core_version, now)
