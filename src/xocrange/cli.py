"""Core contracts, modular installation planning and isolated VM lifecycle."""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from . import __version__
from .documents import json_document, read_bytes, validate
from .errors import XocError
from .events import Context, SOURCES, normalize
from .planner import catalog, plan, write_plan
from .lab import run_lab


def parser():
    cli = argparse.ArgumentParser(prog="xoc", description="xOC Range Core bootstrap CLI")
    cli.add_argument("--version", action="version", version=f"xoc {__version__}")
    cli.add_argument("--root", type=Path, default=Path.cwd(), help="checkout containing components/ and presets/")
    commands = cli.add_subparsers(dest="command", required=True)
    listing = commands.add_parser("catalog", help="show ready/planned components")
    listing.add_argument("--allow-fixtures", action="store_true")
    for name in ("plan", "doctor"):
        sub = commands.add_parser(name, help="validate local installation inputs; never start Docker")
        sub.add_argument("--preset", default="bootstrap")
        sub.add_argument("--include", action="append", default=[])
        sub.add_argument("--without", action="append", default=[])
        sub.add_argument("--allow-fixtures", action="store_true")
        sub.add_argument("--allow-experimental", action="store_true")
        if name == "plan":
            sub.add_argument("--output", help="new directory name beneath .local/plans; omitted means stdout only")
    events = commands.add_parser("events", help="validate or normalize a single bounded source record")
    event_commands = events.add_subparsers(dest="event_command", required=True)
    checking = event_commands.add_parser("validate")
    checking.add_argument("--input", required=True, type=Path)
    converting = event_commands.add_parser("normalize")
    converting.add_argument("--input", required=True, type=Path)
    converting.add_argument("--source", required=True, choices=SOURCES)
    for name in ("tenant-id", "range-id", "source-id", "evidence-ref", "observed-at"):
        converting.add_argument(f"--{name}", required=True)
    lab = commands.add_parser("lab", help="run packet-path checks on a dedicated Ubuntu 26.04 VM")
    lab.add_argument("action", choices=("check", "up", "start", "verify", "down"))
    lab.add_argument("--plan", required=True, help="plan directory name beneath .local/plans")
    lab.add_argument("--isolated-vm", action="store_true", help="confirm this is the dedicated lab VM")
    siem = commands.add_parser("siem", help="local evidence, Wazuh decoding and search")
    siem.add_argument("action", choices=("collect", "once", "status", "query", "evidence", "retry", "credentials"))
    siem.add_argument("--plan")
    siem.add_argument("--store", type=Path, default=Path('/var/lib/xocrange/siem'))
    siem.add_argument("--source", choices=SOURCES)
    siem.add_argument("--limit", type=int, default=20)
    siem.add_argument("--confirmed", action="store_true")
    siem.add_argument("--ref", help="opaque evidence reference; raw evidence is accessible only to the local owner")
    return cli


def run(args):
    if args.command == "siem":
        from .collector import Collector
        from .event_store import Store
        if args.action == 'credentials':
            from .ui_setup import STATE, private_json
            secret=private_json(STATE/'credentials.json')
            return {'url':'https://'+secret['public_host']+'/siem/','username':'admin','password':secret['admin'],'ca_certificate':'/etc/xocrange/ca.crt'}
        if args.action in ('collect', 'once'):
            if not args.plan:
                raise XocError('missing_plan', 'Collection requires a validated --plan.')
            collector = Collector(args.root, args.plan, args.store)
            return collector.run() if args.action == 'collect' else collector.once()
        store = Store(args.store)
        if args.action == 'status':
            return store.status()
        if args.action == 'query':
            return store.query(args.source, args.limit, args.confirmed)
        if args.action == 'retry':
            return store.retry(args.source)
        row = store.db.execute('SELECT ref,source,observed,sha256,raw,error FROM records WHERE ref=?', (args.ref,)).fetchone()
        if not row:
            raise XocError('evidence_absent', 'Evidence was not found or has expired.')
        import base64
        return {**{k: row[k] for k in row.keys() if k != 'raw'}, 'raw_base64': base64.b64encode(row['raw']).decode()}
    if args.command == "lab":
        return run_lab(args.root, args.plan, args.action, args.isolated_vm)
    if args.command == "catalog":
        return {"components": [entry["manifest"] for entry in catalog(args.root, allow_fixtures=args.allow_fixtures).values()]}
    if args.command in ("plan", "doctor"):
        result = plan(args.root, preset=args.preset, include=args.include,
                      without=args.without, allow_fixtures=args.allow_fixtures,
                      allow_experimental=args.allow_experimental)
        if args.command == "doctor":
            return {"status": "configuration-valid", "selected": result["lock"]["selected"],
                    "checks": {"manifests_and_dependencies": "passed", "compose_fragment_policy": "passed",
                               "docker_cli": "present" if shutil.which("docker") else "missing",
                               "docker_daemon": "not-checked", "host_ports_and_resources": "not-checked"},
                    "limitations": result["limitations"]}
        if args.output:
            result["output"] = str(write_plan(args.root, args.output, result))
        return result
    raw = read_bytes(args.input)
    if args.event_command == "normalize":
        context = Context(args.tenant_id, args.range_id, args.source_id, args.evidence_ref, args.observed_at)
        return normalize(args.source, raw, context)
    value = json_document(raw)
    events = value if isinstance(value, list) else [value]
    if not events:
        raise XocError("empty_events", "Expected at least one C1 event.")
    for event in events:
        validate(event, "c1-event")
    return {"valid": True, "events": len(events)}


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        result = run(args)
        print(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False))
        if args.command == "lab" and result["status"] in ("blocked", "failed"):
            return 2
        return 0
    except XocError as exc:
        print(json.dumps({"error": {"code": exc.code, "message": str(exc)}}), file=sys.stderr)
        return 2
    except OSError:
        print(json.dumps({"error": {"code": "filesystem_error", "message": "Cannot access the requested local path."}}), file=sys.stderr)
        return 2
