"""Raw-source delivery to Wazuh, independent of the normalized C1 route."""
import hashlib
import json
import re
import xml.etree.ElementTree as ET

from .documents import canonical, json_document
from .errors import XocError
from .events import SOURCES

LOCATION = re.compile(r'^xoc-native/([a-f0-9]{64})/(' + '|'.join(SOURCES) + r')$')
DECODERS = {'nftables': {'xoc-nftables', 'kernel'}, 'suricata': {'json'},
            'modsecurity': {'json'}, 'osquery': {'json'}, 'sysmon': {'json'},
            'auditd': {'auditd'}, 'apache-access': {'web-accesslog', 'json'},
            'apache-error': {'apache-errorlog'}}
MAX_FRAME = 60000


def json_frame(value):
    # Wazuh's JSON decoder cannot decode arrays containing objects. osquery
    # batches are split into native result records before reaching this check.
    def check(item):
        if isinstance(item, dict):
            for child in item.values(): check(child)
        elif isinstance(item, list):
            if any(isinstance(child, (dict, list)) for child in item):
                raise XocError('native_json_array', 'Native JSON arrays must contain scalar values.')
    check(value)
    return canonical(value).decode()


def frames(source, raw):
    """Return bounded native messages; never manufacture C1 or Windows events."""
    text = raw.decode('utf-8').strip()
    if source == 'modsecurity':
        data = json_document(raw)
        audit = data.get('audit_data', {})
        # AHZ audit logging deliberately omits response headers/status. Only an
        # engine-generated intervention at the START of a message establishes
        # a block. Quoted request data, HTTP 403 and detection-only warnings do
        # not. Replace any supplied reserved field, never trust it as input.
        data['xoc_modsecurity'] = {'intervention': audit.get('engine_mode') == 'ENABLED' and any(
            re.match(r'^Access denied with code [45][0-9]{2} \(phase [1-5]\)\.', message)
            for message in audit.get('messages', []))}
        output = [json_frame(data)]
    elif source == 'suricata':
        output = [json_frame(json_document(raw))]
    elif source == 'osquery':
        data = json_document(raw)
        base = {k: v for k, v in data.items() if k not in ('snapshot', 'diffResults', 'columns', 'action')}
        if 'snapshot' in data:
            rows = [('snapshot', row) for row in data['snapshot']]
        elif 'diffResults' in data:
            rows = [(action, row) for action in ('added', 'removed') for row in data['diffResults'].get(action, [])]
        else:
            rows = [(data['action'], data['columns'])]
        if len(rows) > 256:
            raise XocError('native_row_limit', 'Too many native query rows.')
        output = [json_frame({'osquery': dict(base, action=action, columns=row)})
                  for action, row in rows or [('snapshot', {})]]
    elif source == 'sysmon':
        if '<Event' not in text:
            # C1 validates and retains known sensor diagnostics separately.
            return []
        if '<!' in text:
            raise XocError('native_xml', 'Native XML cannot contain declarations or entities.')
        tree = ET.fromstring(text[text.index('<Event'):])
        for element in tree.iter(): element.tag = element.tag.split('}')[-1]
        system = tree.find('System')
        if system is None or system.find('Provider') is None or system.find('Provider').get('Name') != 'Linux-Sysmon':
            raise XocError('native_provider', 'This live source expects Linux Sysmon.')
        data = {}
        for element in tree.findall('EventData/Data'):
            name = element.get('Name')
            if not name or name in data:
                raise XocError('native_xml', 'Duplicate or unnamed Sysmon field.')
            data[name] = element.text or ''
        output = [json_frame({'sysmon_linux': {
            'provider': 'Linux-Sysmon', 'event_id': int(system.findtext('EventID')),
            'computer': system.findtext('Computer') or '',
            'system_time': system.find('TimeCreated').get('SystemTime', '') if system.find('TimeCreated') is not None else '',
            'eventdata': data}})]
    elif source == 'auditd':
        # Match logcollector's single-message audit grouping; original bytes,
        # including line boundaries and ENRICHED separators, remain in records.
        output = [' '.join(text.replace('\x1d', ' ').splitlines())]
    elif source == 'apache-access' and text.startswith('{'):
        output = [json_frame(json_document(raw))]  # retained legacy JSON format
    elif source in SOURCES:
        output = [text]
    else:
        raise XocError('native_source', 'Unregistered native source.')
    if any(not value or '\x00' in value or '\n' in value or '\r' in value or len(value.encode()) > MAX_FRAME for value in output):
        raise XocError('native_frame_limit', 'Native input exceeds its frame or line budget; original evidence is retained.')
    return output


def register(store, ref, source, raw, events, observed):
    try:
        values = frames(source, raw)
        error = None
    except (XocError, ValueError, KeyError, TypeError, UnicodeError, ET.ParseError) as exc:
        values = []; error = getattr(exc, 'code', 'native_input_invalid')
    for ordinal, value in enumerate(values or [None]):
        identifier = hashlib.sha256(canonical(['native-input/1', ref, ordinal])).hexdigest()
        event = events[ordinal if source == 'osquery' else 0]['event_id'] if events else None
        store.db.execute('''INSERT INTO native_inputs(id,ref,source,ordinal,observed,event_id,frame_sha256,confirmed,decoder,error)
            VALUES (?,?,?,?,?,?,?,?,?,?)''', (identifier, ref, source, ordinal, observed, event,
            hashlib.sha256(value.encode()).hexdigest() if value is not None else None,
            observed if value is None and error is None else None,
            'sensor-diagnostic' if value is None and error is None else None, error))


def pending(store, limit=4096):
    from datetime import datetime, timezone, timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat().replace('+00:00', 'Z')
    query = '''SELECT n.*,r.raw FROM native_inputs n JOIN records r ON r.ref=n.ref
       WHERE n.confirmed IS NULL AND n.error IS NULL AND (n.sent IS NULL OR n.sent<?)
       ORDER BY n.observed {} LIMIT ?'''
    recent = store.db.execute(query.format('DESC'), (cutoff, max(1, limit//4))).fetchall()
    oldest = store.db.execute(query.format('ASC'), (cutoff, limit)).fetchall()
    result = []; seen = set(); cache = {}; size = 0
    for row in [*recent, *oldest]:
        if row['id'] in seen: continue
        seen.add(row['id'])
        if row['ref'] not in cache: cache[row['ref']] = frames(row['source'], row['raw'])
        payload = cache[row['ref']][row['ordinal']]
        if hashlib.sha256(payload.encode()).hexdigest() != row['frame_sha256']:
            raise XocError('native_frame_changed', 'A pending native input differs from its durable definition.')
        size += len(payload.encode())
        if result and size > 8 * 1024**2: break
        result.append({'id': row['id'], 'source': row['source'], 'payload': payload})
        if len(result) == limit: break
    return result


def delivery(store, value):
    match = LOCATION.fullmatch(value.get('location', ''))
    if not match: return None
    row = store.db.execute('SELECT * FROM native_inputs WHERE id=?', (match[1],)).fetchone()
    if row is None or row['source'] != match[2] or row['error'] not in (None, 'native_decoder_missing'):
        raise XocError('native_receipt_identity', 'Native processing record has no matching local input.')
    if 'full_log' in value and hashlib.sha256(value['full_log'].encode()).hexdigest() != row['frame_sha256']:
        raise XocError('native_receipt_mismatch', 'Native processing record differs from the submitted bytes.')
    return row


def confirm(store, archive):
    from .event_store import now
    row = delivery(store, archive)
    if row is None: return
    if not isinstance(archive.get('full_log'), str):
        raise XocError('native_receipt_missing_bytes', 'Processing receipts must include the submitted native message.')
    decoder = archive.get('decoder', {}).get('name')
    if decoder not in DECODERS[row['source']]:
        store.db.execute('UPDATE native_inputs SET error=? WHERE id=?', ('native_decoder_missing', row['id']))
        return
    store.db.execute('UPDATE native_inputs SET confirmed=COALESCE(confirmed,?),decoder=?,error=NULL WHERE id=?', (now(), decoder, row['id']))
