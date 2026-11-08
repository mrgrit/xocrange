"""Root-only explicit Wazuh agent enrollment; no public enrollment daemon."""
import base64
import json
import os
from pathlib import Path
import re
from urllib.parse import urlencode
from .errors import XocError


def items(client, token, path):
    code, result = client.request('GET', path, token=token)
    data = result.get('data', {})
    if code != 200 or data.get('total_failed_items', 0):
        raise XocError('agent_api_failed', 'The Manager rejected the agent request.')
    return data.get('affected_items', [])


def list_agents(client):
    return [{k: row[k] for k in ('id', 'name', 'status', 'version', 'lastKeepAlive', 'os') if k in row}
            for row in items(client, client.authenticate(), '/agents?limit=500')]


def enroll(client, name, output):
    if os.geteuid() != 0:
        raise XocError('root_required', 'Agent keys may only be provisioned by the local administrator.')
    if not re.fullmatch(r'[a-z][a-z0-9-]{2,47}', name):
        raise XocError('invalid_agent_name', 'Use 3–48 lowercase letters, digits and hyphens.')
    output = Path(output)
    if not output.is_absolute() or any(p.is_symlink() for p in (output, *output.parents)) or not output.parent.is_dir():
        raise XocError('unsafe_agent_key', 'Use a direct absolute key path in an existing private directory.')
    if output.parent.stat().st_mode & 0o077 or output.parent.stat().st_uid != 0:
        raise XocError('unsafe_agent_key', 'Agent key directory must be root-owned and mode 0700.')
    token = client.authenticate()
    matching = [row for row in items(client, token, '/agents?'+urlencode({'name':name,'limit':500})) if row.get('name')==name]
    if matching:
        ident = matching[0]['id']
        rows = items(client, token, '/agents/'+ident+'/key')
        key = rows[0].get('key') if len(rows)==1 else None
    else:
        code, result = client.request('POST', '/agents', {'name':name}, token=token)
        value = result.get('data', {})
        ident, key = value.get('id'), value.get('key')
        if code not in (200,201):
            raise XocError('agent_enrollment_failed', 'Agent registration failed; no credentials were logged.')
    try:
        decoded = base64.b64decode(key, validate=True).decode().strip()
        fields = decoded.split()
        if len(fields)!=4 or fields[:2]!=[ident,name] or not re.fullmatch(r'\d{3,8}',ident) or not re.fullmatch('[0-9a-fA-F]{64}',fields[3]):raise ValueError()
    except (ValueError, TypeError):
        raise XocError('invalid_agent_key', 'Manager returned an invalid agent identity.')
    # Atomic create prevents silently replacing an enrolled endpoint's identity.
    payload = (decoded+'\n').encode()
    if output.exists():
        if output.stat().st_mode & 0o077 or output.stat().st_uid!=0 or output.read_bytes()!=payload:
            raise XocError('agent_key_conflict', 'Existing agent key differs or has unsafe permissions.')
    else:
        fd = os.open(output, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(payload);stream.flush();os.fsync(stream.fileno())
    return {'id':ident,'name':name,'key_file':str(output),'transport':'Wazuh secure TCP 1514; Manager API/enrollment ports remain internal'}
