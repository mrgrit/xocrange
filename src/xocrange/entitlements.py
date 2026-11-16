"""Host adapter to the single C7 implementation shipped in the platform image."""
import types
import json
import re
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from . import __version__
from .errors import XocError

DEFAULT = Path('/etc/xocrange/entitlements')


def verifier(root):
    # Only the validated installation source supplies executable verification code.
    # Compile in memory: importing through SourceFileLoader would create a
    # __pycache__ inside the strictly declared platform build context.
    from .documents import within, read_bytes
    path = within(root, 'components/platform/control/entitlements.py')
    module = types.ModuleType('xoc_c7')
    exec(compile(read_bytes(path), str(path), 'exec'), module.__dict__)
    return module


def grant(root, directory=DEFAULT):
    api = verifier(root)
    try:
        return api.load(directory, __version__)
    except (api.Denied, OSError) as exc:
        raise XocError(getattr(exc, 'code', 'entitlement_unavailable'), 'C7 entitlement validation failed.') from exc


REGISTRY = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,252})(?::[0-9]{1,5})?\Z')


def registry_login(root, registry, ca=None, directory=DEFAULT):
    """Log Docker in to the paid module registry with the active license (L17, PACKAGING §8).

    The registry's token service verifies the same signed license and hands out pull tokens only
    for the modules it grants, until it expires. The license goes to `docker login` on stdin;
    Docker keeps it in root's configuration. A registry without a public certificate needs its CA
    (`--ca`), placed in Docker's per-registry trust directory.
    """
    import base64
    if os.geteuid() != 0:
        raise XocError('root_required', 'Registry login requires sudo.')
    if not REGISTRY.fullmatch(registry or ''):
        raise XocError('invalid_registry', 'Give the registry as host or host:port.')
    value = grant(root, directory)
    if value is None:
        raise XocError('commercial_unavailable', 'No Live Fire license is active; Community needs no registry.')
    if value['expired']:
        raise XocError('entitlement_expired', 'The license has expired: installed modules keep read and export, new pulls are refused.')
    if ca is not None:
        data = Path(ca).read_bytes()
        if b'-----BEGIN CERTIFICATE-----' not in data or len(data) > 65536:
            raise XocError('invalid_ca', 'The registry CA must be a PEM certificate.')
        target = Path('/etc/docker/certs.d')/registry
        target.mkdir(parents=True, exist_ok=True, mode=0o755)
        atomic(target/'ca.crt', data)
        (target/'ca.crt').chmod(0o644)
    password = base64.urlsafe_b64encode((directory/'license.json').read_bytes()).rstrip(b'=').decode()
    result = subprocess.run(['docker', '--context', 'default', 'login', registry, '--username', 'license', '--password-stdin'],
                            input=password, capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise XocError('registry_login_failed', 'The registry refused the license: ' + (result.stderr.strip().splitlines() or ['no answer'])[-1][:200])
    return {'status': 'logged_in', 'registry': registry, 'license_id': value['license_id'], 'modules': sorted(value['modules'])}


DOMAIN_GRACE = 14   # days a learner domain keeps working after the license expires (ADR 0011)


def learner_domain(root, directory=DEFAULT, now=None):
    """The learner's lab domain from a valid Live Fire license, or None (Community: xoc.range only)."""
    from datetime import datetime, timedelta, timezone
    try:
        value = grant(root, directory)
    except XocError:
        return None
    if not value or not value.get('domain'):
        return None
    if value['expired']:
        expires = datetime.fromisoformat(value['expires_at'].replace('Z', '+00:00'))
        if (now or datetime.now(timezone.utc)) >= expires + timedelta(days=DOMAIN_GRACE):
            return None
    return value['domain']


COMMUNITY_IDENTITY = ('community', 'local')
_IDENTIFIER = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}')


def collection_identity(root, directory=DEFAULT):
    """C1 tenant/range for newly collected events (ADR-0008 §7).

    A verified commercial grant binds the appliance to its institution and range;
    without one (or if it cannot be verified) Core keeps the Community identity.
    """
    try:
        value = grant(root, directory)
    except XocError:
        return COMMUNITY_IDENTITY
    if not value:
        return COMMUNITY_IDENTITY
    identity = (value.get('institution_id'), value.get('range_id'))
    if all(isinstance(v, str) and _IDENTIFIER.fullmatch(v) for v in identity):
        return identity
    return COMMUNITY_IDENTITY


def authorize(root, manifest, action, directory=DEFAULT):
    if action == 'stop':
        return {'mode': 'stop'}
    api = verifier(root)
    try:
        return api.authorize(grant(root, directory) if api.paid(manifest) else None, manifest, action)
    except api.Denied as exc:
        raise XocError(exc.code, 'The installed entitlement does not permit this operation.') from exc


def atomic(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix='.c7-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(value); stream.flush(); os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def sync_platform(volume, directory=DEFAULT):
    target = volume/'entitlements'
    if target.is_symlink():
        raise XocError('entitlement_path', 'Unexpected entitlement volume path.')
    staging = Path(tempfile.mkdtemp(prefix='.entitlements-', dir=volume))
    try:
        if (directory/'license.json').exists():
            for name in ('license.json', 'identity.json'):
                path = directory/name
                if path.is_symlink():
                    raise XocError('entitlement_path', 'Unexpected entitlement path.')
                atomic(staging/name, path.read_bytes())
            (staging/'trust').mkdir(mode=0o700)
            for path in (directory/'trust').glob('*.pem'):
                if path.is_symlink():
                    raise XocError('entitlement_path', 'Unexpected trust key path.')
                atomic(staging/'trust'/path.name, path.read_bytes())
        for path in [staging, *staging.rglob('*')]:
            os.chown(path, 65532, 65532)
        # Readers fail closed during replacement; no cached, expired permissions.
        if target.exists():
            shutil.rmtree(target)
        staging.rename(target)
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def manage(root, action, *, file=None, key_id=None, institution=None, range_id=None, directory=DEFAULT):
    api = verifier(root)
    if action == 'status':
        value = grant(root, directory)
        if value is None:
            return {'mode': 'community'}
        return {**{k: value[k] for k in ('license_id', 'institution_id', 'range_id', 'tier', 'expires_at', 'expired', 'fingerprint')},
                **{k: value[k] for k in ('domain', 'issuer_id') if value.get(k)}}
    if os.geteuid() != 0:
        raise XocError('root_required', 'Entitlement configuration requires sudo.')
    if any(p.is_symlink() for p in (directory, *directory.parents)):
        raise XocError('entitlement_path', 'Entitlement paths cannot traverse symlinks.')
    try:
        if action == 'trust':
            api.identifier(key_id)
            raw = file.read_bytes()
            # Validate the algorithm before recording an explicitly supplied public key.
            import base64, re
            match = re.fullmatch(rb'-----BEGIN PUBLIC KEY-----\s+([A-Za-z0-9+/=\s]+)-----END PUBLIC KEY-----\s*', raw)
            der = base64.b64decode(b''.join(match[1].split()), validate=True) if match else b''
            if len(der) != 44 or der[:12] != bytes.fromhex('302a300506032b6570032100'):
                raise api.Denied('entitlement_key_type')
            destination = directory/'trust'/(key_id+'.pem')
            if destination.exists() and destination.read_bytes() != raw:
                raise api.Denied('entitlement_key_conflict')
            atomic(destination, raw)
            return {'trusted_key': key_id, 'algorithm': 'Ed25519'}
        envelope = api.read(file)
        identity = {'institution_id': institution, 'range_id': range_id}
        key = api.trust_key_id(envelope)
        verified = api.verify(envelope, {key: (directory/'trust'/(key+'.pem')).read_text()}, identity, __version__)
        if verified['expired']:
            raise api.Denied('entitlement_expired')
        # Activate both files in one directory rename, preserving public trust roots.
        staging = Path(tempfile.mkdtemp(prefix='.activation-', dir=directory.parent))
        previous = directory.with_name('.entitlements-previous')
        platform_volume = None
        try:
            shutil.copytree(directory/'trust', staging/'trust')
            atomic(staging/'identity.json', api.canonical(identity))
            atomic(staging/'license.json', api.canonical(envelope))
            if previous.exists():
                raise api.Denied('entitlement_recovery_required')
            directory.rename(previous)
            try:
                staging.rename(directory)
                state = Path('/var/lib/xocrange/last-install.json')
                if state.exists():
                    from .lab import Docker
                    from .ui_setup import owned_volume
                    installed = json.loads(state.read_text())
                    engine = Docker(Path(installed['release'])/'.local/plans'/installed['plan']/'compose.yaml', 'xoc-core-security-path')
                    platform_volume = owned_volume(engine, 'xoc-core-security-path', 'platform-config')
                    sync_platform(platform_volume, directory)
            except BaseException:
                if directory.exists():
                    shutil.rmtree(directory)
                previous.rename(directory)
                if platform_volume is not None:
                    try:
                        sync_platform(platform_volume, directory)
                    except BaseException:
                        # A failed publication must not leave the newly rejected
                        # grant active in the independent web verifier.
                        target = platform_volume/'entitlements'
                        if target.exists() and not target.is_symlink():
                            shutil.rmtree(target)
                raise
            shutil.rmtree(previous)
        finally:
            if staging.exists():
                shutil.rmtree(staging)
        # Events collected from now on carry the activated institution/range (ADR-0008 §7).
        import subprocess
        subprocess.run(['systemctl', 'try-restart', 'xocrange-collector'], capture_output=True, timeout=60)
        return manage(root, 'status', directory=directory)
    except api.Denied as exc:
        raise XocError(exc.code, 'Entitlement activation was rejected.') from exc
