#!/usr/bin/env python3
"""Resend four already-analyzed raw inputs and verify first-alert preservation."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import time

from siem_lifecycle import Installed, STATE, installation_lock, private_directory, save_new, wait_for
from xocrange.documents import canonical
from xocrange.native_alerts import document
from xocrange.native_input import frames

# Current releases store the xoc annotation; earlier ones stored a full document.
INPUT_ID="COALESCE(json_extract(a.annotation,'$.input_id'),json_extract(NULLIF(a.document,''),'$.xoc.input_id'))"


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--isolated-vm',action='store_true')
    args=parser.parse_args()
    with installation_lock():
        installed=Installed(args.isolated_vm);store=installed.store
        wait_for(lambda:store.status()['status']=='ready',300,'Start replay verification with healthy queues')
        probes=[]
        for source,rule in [('suricata','86601'),('modsecurity','119672'),('osquery','24010'),('sysmon','111201')]:
            row=store.db.execute(f'''SELECT n.id,n.source,n.ordinal,r.raw,a.id AS alert_id,a.sha256,a.raw AS alert_raw,a.document,a.annotation
              FROM native_inputs n JOIN records r ON r.ref=n.ref JOIN wazuh_alerts a ON a.event_id=n.event_id
              WHERE n.source=? AND n.confirmed IS NOT NULL AND a.indexed IS NOT NULL
              AND {INPUT_ID}=n.id AND json_extract(CAST(a.raw AS TEXT),'$.rule.id')=?
              ORDER BY n.observed DESC LIMIT 1''',(source,rule)).fetchone()
            if row is None:raise RuntimeError('Missing live native alert for '+source)
            probe=dict(row);probe['document']=document({'raw':row['alert_raw'],'document':row['document'],'annotation':row['annotation']})
            probes.append(probe)
        payload=[{'id':p['id'],'source':p['source'],'payload':frames(p['source'],p['raw'])[p['ordinal']]} for p in probes]
        volume=json.loads(installed.engine.run(['volume','inspect',installed.project+'_siem-logs']))[0]['Mountpoint']
        archive=Path(volume)/'archives/archives.json'
        inode=archive.stat().st_ino;offset=archive.stat().st_size
        result=subprocess.run(installed.engine.compose+['exec','-T','--user','999:999','siem',
            '/var/ossec/framework/python/bin/python3','-B','/usr/local/lib/xoc-native-queue.py'],
            input=b''.join(canonical(p)+b'\n' for p in payload),capture_output=True,timeout=30,check=True)
        assert result.stdout.decode().splitlines()==[p['id'] for p in probes]
        receipts={};deadline=time.monotonic()+90
        while time.monotonic()<deadline:
            if archive.stat().st_ino!=inode:raise RuntimeError('Archive rotated during replay; rerun with a new report')
            with archive.open('rb') as stream:stream.seek(offset);lines=stream.readlines()
            for line in lines:
                if not line.endswith(b'\n'):continue
                value=json.loads(line)
                for p in payload:
                    if value.get('location')=='xoc-native/'+p['id']+'/'+p['source'] and value.get('full_log')==p['payload']:
                        receipts[p['id']]=value
            if len(receipts)==4:break
            time.sleep(2)
        # A later committed alert-file cursor establishes that the collector
        # read the replay, rather than merely observing unchanged row counts.
        alert_stat=(Path(volume)/'alerts/alerts.json').stat();alert_size=alert_stat.st_size
        cursor_key=f'wazuh-alerts:{installed.project}_siem-logs:{alert_stat.st_dev}:{alert_stat.st_ino}'
        def consumed():
            cursor=store.cursor(cursor_key) or {}
            return cursor.get('offset',0)>=alert_size and store.status()['status']=='ready'
        wait_for(consumed,180,'Collector did not consume replay alerts')
        checks={}
        for p in probes:
            rows=store.db.execute(f"SELECT a.id,a.raw,a.sha256,a.document,a.annotation,a.indexed FROM wazuh_alerts a WHERE {INPUT_ID}=?",(p['id'],)).fetchall()
            checks[p['source']]=p['id'] in receipts and len(rows)==1 and rows[0]['id']==p['alert_id'] and rows[0]['sha256']==p['sha256'] and hashlib.sha256(rows[0]['raw']).hexdigest()==p['sha256'] and document(rows[0])==p['document'] and bool(rows[0]['indexed'])
        code,data=installed.client.request('POST','/wazuh-alerts-4.x-*/_search',{'size':0,'track_total_hits':True,
            'query':{'terms':{'xoc.input_id':[p['id'] for p in probes]}}})
        checks['four_unique_index_documents']=code==200 and data.get('hits',{}).get('total',{}).get('value')==4
        report={'status':'passed' if all(checks.values()) else 'failed','checks':checks,'raw_inputs_replayed':4}
        directory=STATE/'validation'/'native-replay';private_directory(directory)
        save_new(directory/(datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')+'.json'),report)
        print(json.dumps(report,indent=2));return 0 if report['status']=='passed' else 2


if __name__=='__main__':raise SystemExit(main())
