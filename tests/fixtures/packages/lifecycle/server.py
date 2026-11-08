"""Harmless private HTTP status and one EVE-format contract test event."""
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

EVENT = {'timestamp':datetime.now(timezone.utc).isoformat(), 'event_type':'alert',
         'src_ip':'192.0.2.10', 'src_port':10000, 'dest_ip':'198.51.100.20', 'dest_port':80,
         'proto':'TCP', 'alert':{'signature_id':1999999, 'signature':'xOC lifecycle fixture only',
                               'category':'Module acceptance', 'severity':3, 'action':'allowed'}}
print(json.dumps(EVENT), flush=True)

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        value = EVENT if self.path == '/event' else {'status':'ready', 'fixture':True}
        raw = json.dumps(value).encode()
        self.send_response(200); self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(raw))); self.end_headers(); self.wfile.write(raw)
    def log_message(self, *args): pass

HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
