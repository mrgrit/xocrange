"""One bounded HTTP request for an isolated lab; JSON includes observed outcome."""
import argparse
import http.client
import ipaddress
import json

parser = argparse.ArgumentParser()
parser.add_argument("--address", default="172.29.10.1")
parser.add_argument("--port", type=int, default=8080)
parser.add_argument("--host", choices=["core.xoc.test", "sample.xoc.test"], default="core.xoc.test")
parser.add_argument("--marker", choices=["ips-block", "waf-block"])
args = parser.parse_args()
ipaddress.IPv4Address(args.address)
connection = http.client.HTTPConnection(args.address, args.port, timeout=3)
headers = {"Host": args.host, "Connection": "close", "X-Forwarded-For": "203.0.113.250"}
if args.marker:
    headers["X-Xoc-Probe"] = args.marker
try:
    connection.request("GET", "/", headers=headers)
    response = connection.getresponse()
    result = {"status": response.status, "body": response.read(16384).decode("utf-8", errors="replace")}
except (OSError, http.client.HTTPException) as exc:
    result = {"status": None, "error": type(exc).__name__}
finally:
    connection.close()
print(json.dumps(result))
