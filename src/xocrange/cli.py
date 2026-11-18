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


def learner_targets(root, selected, public_host, domain=None):
    """Hosts-only learner names (NAMING: xoc.range) for installed practice targets, and the
    learner's own lab domain with a Live Fire license (ADR 0011)."""
    import ipaddress
    entries = catalog(root)
    ids = sorted(t["id"] for key in selected if key in entries
                 and entries[key]["manifest"]["kind"] == "component"
                 for t in entries[key]["manifest"].get("http_targets", []))
    names = [i + ".xoc.range" for i in ids] + ([domain] + [f"{i}.{domain}" for i in ids] if domain and ids else [])
    try:
        ipaddress.ip_address(public_host)
        hosts = f"{public_host} {' '.join(names)}" if names else None
    except ValueError:
        hosts = None
    return {"targets": [{"host": n, "url": "https://" + n + "/"} for n in names],
            "hosts_line": hosts,
            "note": "Add hosts_line to the learner PC's hosts file (or an internal DNS zone) and trust "
                    "/etc/xocrange/ca.crt. Traffic passes fw -> IPS -> WAF and is recorded in the SIEM."}


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
    platform = commands.add_parser('platform', help='Local platform administrator access')
    platform.add_argument('action', choices=['credentials', 'targets'])
    licensing = commands.add_parser('license', help='Offline C7 verification and public trust keys')
    licensing.add_argument('action', choices=['status', 'trust', 'activate'])
    licensing.add_argument('--file', type=Path)
    licensing.add_argument('--key-id')
    licensing.add_argument('--institution')
    licensing.add_argument('--range', dest='range_id')
    modules = commands.add_parser('module', help='Install/remove selected modules; preserve settings and evidence')
    modules.add_argument('action', choices=['list','add','upgrade','remove','credentials','login'])
    modules.add_argument('identifier', nargs='?')
    modules.add_argument('--package', type=Path)
    modules.add_argument('--source', type=Path, help='upgrade: also update Core from this source tree in the same transaction')
    modules.add_argument('--preview', action='store_true')
    modules.add_argument('--from', dest='source_dir', type=Path, help='credentials: directory with range-control.url, client.crt, client.key, ca.crt')
    modules.add_argument('--registry', help='login: paid module registry host[:port]; the active license is the credential')
    modules.add_argument('--ca', type=Path, help='login: CA certificate of a registry that has no public certificate')
    evidence = commands.add_parser('evidence', help='Read-only evidence socket for entitled modules (ADR-0008)')
    evidence.add_argument('action', choices=['serve'])
    backup = commands.add_parser('backup', help='Consistent private backup, verification and transactional restore')
    backup.add_argument('action', choices=['create','verify','restore'])
    backup.add_argument('path', type=Path)
    update = commands.add_parser('update', help='Validate and install a local release with automatic rollback')
    update.add_argument('--source', required=True, type=Path)
    update.add_argument('--preview', action='store_true')
    commands.add_parser('recover', help='Restore the durable checkpoint after an interrupted operation')
    agents = commands.add_parser('agents', help='Local privileged Wazuh agent enrollment and status')
    agents.add_argument('action', choices=['list', 'enroll'])
    agents.add_argument('--plan', required=True)
    agents.add_argument('--name')
    agents.add_argument('--output', type=Path)
    lab = commands.add_parser("lab", help="run packet-path checks on a dedicated Ubuntu 26.04 VM")
    lab.add_argument("action", choices=("check", "up", "start", "resume", "verify", "down"))
    lab.add_argument("--plan", required=True, help="plan directory name beneath .local/plans")
    lab.add_argument("--isolated-vm", action="store_true", help="confirm this is the dedicated lab VM")
    siem = commands.add_parser("siem", help="local evidence, Wazuh decoding and search")
    siem.add_argument("action", choices=("collect", "once", "status", "query", "evidence", "retry", "credentials", "clear"))
    siem.add_argument("--yes", action="store_true", help="clear: confirm removing all collected evidence and device logs")
    siem.add_argument("--plan")
    siem.add_argument("--store", type=Path, default=Path('/var/lib/xocrange/siem'))
    siem.add_argument("--source", choices=SOURCES)
    siem.add_argument("--limit", type=int, default=20)
    siem.add_argument("--confirmed", action="store_true")
    siem.add_argument("--ref", help="opaque evidence reference; raw evidence is accessible only to the local owner")
    return cli


def run(args):
    if args.command == 'recover':
        from .operations import operation_lock, recover
        with operation_lock():
            return recover()
    if args.command == 'backup':
        from . import operations as ops
        if args.action == 'verify':
            value = ops.verify_backup(args.path)
            return {'status':'verified', 'archives':len(value['files']), 'created_at':value['created_at'], 'portable':value['portable']}
        with ops.operation_lock():
            return ops.create(args.path) if args.action == 'create' else ops.restore(args.path)
    if args.command in ('module','update'):
        from . import lifecycle, operations as ops
        if args.command == 'update':
            value = lifecycle.change(args.root, 'update', source=args.source, preview=args.preview)
            if not args.preview:
                from .evidence import reload_service
                reload_service()
            return value
        if args.action == 'login':
            from .entitlements import registry_login
            if not args.registry:
                raise XocError('usage', 'xoc module login --registry <host[:port]> [--ca <file>]')
            return registry_login(args.root, args.registry, args.ca)
        if args.action == 'credentials':
            from .evidence import install_credentials
            if not args.identifier or not args.source_dir:
                raise XocError('usage', 'xoc module credentials <id> --from <dir>')
            return install_credentials(args.identifier, args.source_dir)
        if args.action == 'list':
            state = ops.installed()
            return {'selected':state['selected'], 'release':state['release']}
        value = lifecycle.change(args.root, args.action, args.identifier, args.package,
                                 args.source.absolute() if args.source else None, preview=args.preview)
        if not args.preview:
            from .evidence import reload_service
            reload_service()
        return value
    if args.command == 'evidence':
        from .evidence import serve
        return serve()
    if args.command == 'license':
        from .entitlements import manage
        if args.action != 'status' and not args.file:
            raise XocError('missing_arguments', 'A public key or signed entitlement --file is required.')
        if args.action == 'status':
            return manage(args.root, args.action)
        from .operations import operation_lock
        with operation_lock():
            return manage(args.root, args.action, file=args.file, key_id=args.key_id, institution=args.institution, range_id=args.range_id)
    if args.command == 'platform':
        from .platform_setup import STATE
        from .ui_setup import private_json
        secret = private_json(STATE/'credentials.json')
        if args.action == 'targets':
            from .operations import installed
            from .entitlements import learner_domain
            return learner_targets(args.root, installed()['selected'], secret['public_host'], learner_domain(args.root))
        result = {'url':'https://'+secret['public_host']+'/core/', 'username':'admin', 'password':secret.get('admin_password',secret['bootstrap_password']), 'ca_certificate':'/etc/xocrange/ca.crt', 'note':'Initial credentials; if changed in the UI, use the password you chose.'}
        if secret.get('office_password'):
            result['office_pc'] = {'ssh':'ssh -p 2222 '+secret['office_username']+'@'+secret['public_host'], 'username':secret['office_username'], 'password':secret['office_password']}
        return result
    if args.command == 'agents':
        from .lab import Docker, checked_plan
        from .manager_api import ManagerClient
        from .agents import enroll, list_agents
        directory, result = checked_plan(args.root, args.plan)
        if 'siem' not in result['lock']['selected']:
            raise XocError('siem_not_selected', 'Agent enrollment requires the selected SIEM.')
        client = ManagerClient(Docker(directory/'compose.yaml', result['compose']['name']), result['compose']['name'])
        if args.action == 'list': return {'agents':list_agents(client)}
        if not args.name or not args.output: raise XocError('missing_arguments', 'Enrollment requires --name and private --output.')
        return enroll(client, args.name, args.output)
    if args.command == "siem":
        from .collector import Collector
        from .event_store import Store
        if args.action == 'credentials':
            from .ui_setup import STATE, private_json
            secret=private_json(STATE/'credentials.json')
            return {'url':'https://'+secret['public_host']+'/siem/','username':'admin','password':secret['admin'],'ca_certificate':'/etc/xocrange/ca.crt'}
        if args.action == 'clear':
            from .operations import operation_lock
            from .siem_clear import clear
            with operation_lock():
                return clear(args.store, confirmed=args.yes)
        if args.action in ('collect', 'once'):
            if not args.plan:
                raise XocError('missing_plan', 'Collection requires a validated --plan.')
            collector = Collector(args.root, args.plan, args.store)
            try:
                return collector.run() if args.action == 'collect' else collector.once()
            finally:
                collector.close()
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
