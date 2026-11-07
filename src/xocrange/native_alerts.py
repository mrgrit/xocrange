"""Durable export of original Wazuh alerts, alongside (never into) C1 ingestion."""
import hashlib
import json

from .documents import canonical
from .errors import XocError
from .event_store import now


def accept(store,raw):
    alert=json.loads(raw)
    if not all(isinstance(v,str) and v for v in (alert.get('id'),alert.get('timestamp'),alert.get('manager',{}).get('name'))):
        raise XocError('native_alert_format','A Wazuh alert is missing its native identity.')
    identity=hashlib.sha256(canonical([alert['manager']['name'],alert['id'],alert['timestamp']])).hexdigest()
    digest=hashlib.sha256(raw).hexdigest()
    existing=store.db.execute('SELECT sha256 FROM wazuh_alerts WHERE id=?',(identity,)).fetchone()
    if existing:
        if existing[0]!=digest:raise XocError('native_alert_conflict','An existing Wazuh alert has different bytes.')
        return identity
    event_id=alert.get('data',{}).get('event_id')
    row=store.db.execute('SELECT ref FROM events WHERE id=? AND confirmed IS NOT NULL',(event_id,)).fetchone() if isinstance(event_id,str) else None
    link={'event_id':event_id,'evidence_ref':row['ref']} if row else {}
    document=dict(alert)
    document['@timestamp']=alert['timestamp']
    document['xoc']={'native_alert_id':identity,**link}
    store.db.execute('INSERT INTO wazuh_alerts(id,observed,raw,sha256,document,event_id) VALUES (?,?,?,?,?,?)',
                     (identity,now(),raw,digest,canonical(document).decode(),event_id if row else None))
    return identity


def export(store,client):
    rows=store.db.execute('SELECT id,observed,document FROM wazuh_alerts WHERE indexed IS NULL ORDER BY observed DESC LIMIT 4096').fetchall()
    if not rows:return 'ready'
    lines=[];selected=[];size=0
    for row in rows:
        chunk=json.dumps({'index':{'_index':'wazuh-alerts-4.x-'+row['observed'][:10].replace('-','.'),'_id':row['id']}})+'\n'+row['document']+'\n'
        size+=len(chunk.encode())
        if selected and size>8*1024**2:break
        lines.append(chunk);selected.append(row)
    status,reply=client.request('POST','/_bulk',''.join(lines),content_type='application/x-ndjson')
    items=reply.get('items',[])
    if status!=200 or len(items)!=len(selected):raise XocError('native_indexer_rejected','Native alert batch was not acknowledged.')
    failed=False
    with store.transaction():
        for row,item in zip(selected,items):
            ack=item.get('index',{})
            if ack.get('_id')!=row['id']:raise XocError('native_indexer_mismatch','Native alert acknowledgment has the wrong ID.')
            if ack.get('status') in (200,201):store.db.execute('UPDATE wazuh_alerts SET indexed=? WHERE id=?',(now(),row['id']))
            else:failed=True
    return 'native_indexer_rejected' if failed else 'ready'
