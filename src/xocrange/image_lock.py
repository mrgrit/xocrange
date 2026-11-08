"""Freeze the resolved local images separately from the portable source plan."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import yaml
from .documents import canonical, json_document, read_bytes, yaml_document
from .errors import XocError
from .entitlements import atomic


def retain(images):
    # Docker's containerd image store may collect an untagged image after its
    # final container is removed, even though an older plan still needs it.
    for service, item in images.items():
        if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]*', service) or not re.fullmatch(r'sha256:[0-9a-f]{64}', item['id']):
            raise XocError('image_identity', 'Invalid retained image identity.')
        tag = 'xocrange-retained/'+service.lower()+':'+item['id'][7:]
        result = subprocess.run(['docker', '--context', 'default', 'image', 'tag', item['id'], tag], capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise XocError('image_retention', 'A required image could not be retained before changing the installation.')


def capture(directory):
    compose = yaml_document(directory/'compose.yaml')
    images = {}
    for service, definition in compose['services'].items():
        reference = definition.get('image', compose['name']+'-'+service)
        result = subprocess.run(['docker', '--context', 'default', 'image', 'inspect', reference], capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise XocError('image_missing', 'Build or pull every selected service before freezing images.')
        item, = json.loads(result.stdout)
        images[service] = {'id': item['Id'], 'reference': reference, 'repo_digests': sorted(item.get('RepoDigests') or [])}
    plan_id = json_document(read_bytes(directory/'plan.lock.json'))['plan_id']
    value = {'schema_version': 'xoc.images/0.1.0', 'plan_id': plan_id, 'services': images}
    value['sha256'] = hashlib.sha256(canonical(value)).hexdigest()
    target = directory/'images.lock.json'
    if target.exists() and json_document(read_bytes(target)) != value:
        raise XocError('images_already_locked', 'Existing image identities cannot be silently replaced. Create a new release plan.')
    retain(images)
    atomic(target, canonical(value))
    atomic(directory/'compose.images.yaml', yaml.safe_dump(override(value)).encode())
    return value


def override(value):
    return {'services': {name: {'image': item['id'], 'pull_policy': 'never'} for name, item in value['services'].items()}}


def checked(directory):
    path = directory/'images.lock.json'
    if not path.exists():
        return None
    value = json_document(read_bytes(path))
    try:
        digest = value.pop('sha256')
        lock = json_document(read_bytes(directory/'plan.lock.json'))
        compose = yaml_document(directory/'compose.yaml')
        if value['schema_version'] != 'xoc.images/0.1.0' or value['plan_id'] != lock['plan_id'] or digest != hashlib.sha256(canonical(value)).hexdigest():
            raise ValueError()
        if set(value['services']) != set(compose['services']):
            raise ValueError()
        if any(not re.fullmatch(r'sha256:[0-9a-f]{64}', item['id']) for item in value['services'].values()):
            raise ValueError()
        if yaml_document(directory/'compose.images.yaml') != override(value):
            raise ValueError()
    except (KeyError, TypeError, ValueError) as exc:
        raise XocError('image_lock_invalid', 'The image lock and Compose override must match the selected plan.') from exc
    return directory/'compose.images.yaml'
