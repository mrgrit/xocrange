"""Offline, deterministic bootstrap planner. It never invokes Docker."""
from __future__ import annotations

import copy
import hashlib
import json
import re
import shutil
from pathlib import Path

import yaml

from . import __version__
from .documents import canonical, read_bytes, validate, within, yaml_document
from .errors import XocError
from .network_policy import attach_http_targets, backend_network, check_addresses, security_role_policy
from .registry import registrations

# Unmodified upstream practice apps; reviewed against target-compose-fragment.
PRACTICE_TARGETS = ("target-juice", "target-dvwa")


def compatible(requirement: str, version=__version__):
    current = tuple(map(int, version.split(".")))
    terms = requirement.split()
    if not terms:
        raise XocError("invalid_version_range", "An explicit Core version range is required.")
    result = True
    for term in terms:
        match = re.fullmatch(r"(>=|<=|>|<|=)?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", term)
        if not match:
            raise XocError("invalid_version_range", "Use space-separated numeric version comparisons.")
        op = match[1] or "="
        wanted = tuple(map(int, match.groups()[1:]))
        result &= {"=": current == wanted, ">=": current >= wanted, "<=": current <= wanted,
                   ">": current > wanted, "<": current < wanted}[op]
    return result


def catalog(root: Path, *, allow_fixtures=False):
    root = root.resolve()
    result = {}
    locations = [("components/*/component.yaml", "component"), ("modules.d/*/module.yaml", "module")]
    if allow_fixtures:
        locations.append(("tests/fixtures/modules/*/module.yaml", "fixture"))
    for pattern, kind in locations:
        for path in sorted(root.glob(pattern)):
            checked = within(root, str(path.relative_to(root)))
            descriptor = validate(yaml_document(checked), "manifest")
            if descriptor["kind"] != kind:
                raise XocError("invalid_kind", "Descriptor kind must match its installation directory.")
            identifier = descriptor["id"]
            if identifier in result:
                raise XocError("duplicate_component", f"Duplicate component ID: {identifier}")
            result[identifier] = {"manifest": descriptor, "path": checked}
    if "platform" not in result or result["platform"]["manifest"]["kind"] != "component":
        raise XocError("missing_platform", "The mandatory platform descriptor is missing.")
    return result


def ordered(nodes, dependencies, *, code="dependency_cycle"):
    visiting, done, result = set(), set(), []

    def visit(node):
        if node in visiting:
            raise XocError(code, "A dependency cycle prevents planning.")
        if node in done:
            return
        visiting.add(node)
        for required in sorted(dependencies(node)):
            visit(required)
        visiting.remove(node)
        done.add(node)
        result.append(node)

    for node in sorted(nodes):
        visit(node)
    return result


def reject_interpolation(value):
    if isinstance(value, str) and "$" in value:
        raise XocError("environment_interpolation", "Bootstrap fragments must use explicit values, without dollar interpolation.")
    if isinstance(value, dict):
        for child in value.values():
            reject_interpolation(child)
    elif isinstance(value, list):
        for child in value:
            reject_interpolation(child)


EVIDENCE = "evidence-query"
ACTIVITY_VOLUME, ACTIVITY_TARGET = "activity-{}", "/run/xoc-activity"


FACILITY = "facility-state"
# ADR 0014: the facility module writes its state for the platform to read, and reads the
# requests the platform writes. Files only: no network path and no socket between them.
FACILITY_STATE = ("facility-state", "/run/xoc-facility")
FACILITY_REQUESTS = ("facility-requests", "/run/xoc-facility-requests")


def evidence_volumes(identifier):
    """(volume, mount target) pairs a module receives under ADR-0008."""
    return ((f"evidence-{identifier}", "/run/xoc-evidence"), (f"module-{identifier}-credentials", "/run/xoc-module"))


def plan(root: Path, *, preset="bootstrap", include=(), without=(), allow_fixtures=False, allow_experimental=False,
         entitlement_dir=None, entitlement_action='install'):
    root = root.resolve()
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", preset):
        raise XocError("invalid_preset", "Preset must be a simple identifier.")
    preset_path = within(root, f"presets/{preset}.yaml")
    selection = validate(yaml_document(preset_path), "preset")
    entries = catalog(root, allow_fixtures=allow_fixtures)
    requested = set(selection["components"]) | set(include) | {"platform"}
    excluded = set(without)
    if not (requested | excluded).issubset(entries):
        raise XocError("unknown_component", "An included or excluded component is not in the catalog.")
    if "platform" in excluded:
        raise XocError("required_component", "The platform component cannot be excluded.")
    if set(include) & excluded:
        raise XocError("conflicting_selection", "A component cannot be both included and excluded.")
    requested -= excluded

    def dependencies(identifier):
        if identifier not in entries:
            raise XocError("missing_dependency", "A required component is missing from the catalog.")
        if identifier in excluded:
            raise XocError("required_component", f"An excluded component is required: {identifier}")
        return entries[identifier]["manifest"]["requires"]["components"]

    selected = ordered(requested, dependencies)
    capabilities = set()
    config_owners = {}
    for identifier in selected:
        manifest = entries[identifier]["manifest"]
        from .entitlements import authorize, DEFAULT
        authorize(root, manifest, entitlement_action, entitlement_dir or DEFAULT)
        if not compatible(manifest["core"]):
            raise XocError("core_incompatible", f"Component is incompatible with this Core version: {identifier}")
        if set(manifest["conflicts"]) & set(selected):
            raise XocError("component_conflict", f"A selected component declares a conflict: {identifier}")
        if manifest["status"] == "experimental" and not allow_experimental:
            raise XocError("experimental_component", f"Explicit --allow-experimental is required: {identifier}")
        if manifest["status"] == "planned":
            raise XocError("component_not_ready", f"Component has a plan but no runnable implementation yet: {identifier}")
        capabilities.update(manifest["provides"])
        for key in manifest["config_keys"]:
            if key in config_owners:
                raise XocError("config_conflict", "Multiple components declare the same configuration key.")
            config_owners[key] = identifier
    for identifier in selected:
        if not set(entries[identifier]["manifest"]["requires"]["capabilities"]).issubset(capabilities):
            raise XocError("missing_capability", f"A required capability has no selected provider: {identifier}")

    compose = {"name": f"xoc-core-{preset}", "services": {}, "networks": {}}
    inputs = {}
    owners = {}

    def record(path):
        relative = str(path.relative_to(root))
        inputs[relative] = hashlib.sha256(read_bytes(path)).hexdigest()

    record(preset_path)
    if 'academy-reader' in selected:
        from .academy_content import catalog as academy_catalog
        from .content_module import verify
        try:
            verify(root/'contents')
        except (ValueError, OSError) as exc:
            raise XocError('content_module', 'Bundled content does not match contents/module.json: '+str(exc)) from exc
        for relative in ('contents/module.json','contents/guides/core-introduction.json','contents/catalog/academy.json','contents/catalog/subjects.json'):
            record(root/relative)
        _, content_files = academy_catalog(root)
        for path in content_files:
            # The catalog bounds/verifies binary screenshots separately from
            # the 1 MiB JSON/manifest limit; hash their exact installed bytes.
            inputs[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    for identifier in selected:
        entry = entries[identifier]
        manifest, manifest_path = entry["manifest"], entry["path"]
        package = manifest_path.parent
        record(manifest_path)
        allowed_build_files = {manifest_path}
        for relative in manifest["build_inputs"]:
            source = within(package, relative)
            record(source)
            allowed_build_files.add(source)
        if "compose" not in manifest:
            raise XocError("missing_compose", f"Ready component must provide a Compose fragment: {identifier}")
        fragment_path = within(package, manifest["compose"])
        record(fragment_path)
        allowed_build_files.add(fragment_path)
        security_path = identifier == "security-path" and manifest["kind"] == "component"
        if security_path and (manifest["status"] != "experimental" or not allow_experimental):
            raise XocError("experimental_component", "The security-path runtime requires explicit experimental selection.")
        siem = identifier == "siem" and manifest["kind"] == "component"
        siem_ui = identifier == "siem-ui" and manifest["kind"] == "component"
        schema = "security-compose-fragment" if security_path else "siem-compose-fragment" if siem else "siem-ui-compose-fragment" if siem_ui else "management-compose-fragment" if identifier == "management" else "console-compose-fragment" if identifier in ("console-fw","console-ips","console-waf","portal","noc","academy-reader") else "target-compose-fragment" if identifier in PRACTICE_TARGETS and manifest["kind"] == "component" else "office-compose-fragment" if identifier == "office-pc" and manifest["kind"] == "component" else "attacker-compose-fragment" if identifier == "attacker" and manifest["kind"] == "component" else "compose-fragment"
        fragment = validate(yaml_document(fragment_path), schema)
        if schema == "compose-fragment":
            # Only the reviewed management ingress publishes on external
            # interfaces; anything else would bypass fw/IPS/WAF and Core login.
            for service in fragment["services"].values():
                if any(port["host_ip"] not in ("127.0.0.1", "::1") for port in service.get("ports", [])):
                    raise XocError("public_port", "Extensions may publish host ports on loopback only; learner access goes through the ingress.")
        if siem:
            service = fragment["services"]["siem"]
            if set(fragment["networks"]) != {"int", "dmz"} or fragment["networks"]["int"] != {"internal": True} or service["networks"] != {"int": {}, "dmz": {"ipv4_address": "10.20.32.100"}} or any(k in service for k in ("ports", "sysctls", "environment", "command", "entrypoint")):
                raise XocError("siem_privileges", "SIEM has only reviewed private Manager volumes, its internal network and its agent address on the dmz.")

        if security_path:
            security_role_policy(fragment)
        for volume, definition in fragment.get("volumes", {}).items():
            if volume in compose.setdefault("volumes", {}):
                raise XocError("volume_conflict", "Persistent volume names must have one owner.")
            compose["volumes"][volume] = definition
        reject_interpolation(fragment)
        if set(fragment["networks"]) != set(manifest["networks"]):
            raise XocError("undeclared_network", "Fragment networks must match the descriptor declaration.")
        for name, network in fragment["networks"].items():
            if name in compose["networks"] and compose["networks"][name] != network:
                raise XocError("network_conflict", "Selected fragments disagree on network settings.")
            compose["networks"][name] = network
        for name, service in fragment["services"].items():
            if name in compose["services"]:
                raise XocError("service_conflict", f"Duplicate service name: {name}")
            if not set(service["networks"]).issubset(manifest["networks"]):
                raise XocError("undeclared_network", "A service uses an undeclared network.")
            if not set(service.get("environment", {})).issubset(manifest["config_keys"]):
                raise XocError("undeclared_config", "Environment keys must be declared by their component.")
            service = copy.deepcopy(service)
            if "build" in service:
                context = within(package, service["build"]["context"], require_file=False)
                if not context.is_dir():
                    raise XocError("missing_context", "Build context must be an existing package directory.")
                dockerfile = within(context, service["build"]["dockerfile"])
                if dockerfile not in allowed_build_files:
                    raise XocError("untracked_build_input", "Dockerfile must be a declared build input.")
                # Every file sent to Docker must be accounted for, including .dockerignore.
                for candidate in context.rglob("*"):
                    if candidate.is_symlink():
                        raise XocError("build_symlink", "Build contexts cannot contain symlinks in v0.1.")
                    if candidate.is_file() and candidate not in allowed_build_files:
                        raise XocError("untracked_build_input", "Build context contains an undeclared file.")
                service["build"]["context"] = str(context)
            compose["services"][name] = service
            owners[name] = identifier

    if 'management' in selected:
        compose['services']['web']['volumes'] += ['web-tls:/run/xoc-tls:ro', 'platform-socket:/run/xoc-platform-socket:ro']
        compose['services']['web']['environment']['XOC_MANAGEMENT'] = '1'
        compose['services']['platform'].update(user='65532:33', volumes=['platform-config:/run/xoc-platform:ro', 'platform-data:/var/lib/xoc-platform', 'platform-socket:/run/xoc-platform-socket'], tmpfs=['/tmp:size=32m,mode=1777'])
        compose.setdefault('volumes', {})['platform-observation'] = {}
        compose['services']['platform']['volumes'].append('platform-observation:/run/xoc-observation:ro')
    if 'management' in selected:
        for device, service in (('fw','fw'), ('ips','ips'), ('waf','web')):
            # Keep persistent device policy even when its optional GUI is unselected.
            volume = 'console-' + device + '-state'
            compose.setdefault('volumes', {})[volume] = {}
            compose['services'][service].setdefault('volumes', []).append(volume + ':/var/lib/xoc-console')
            compose['services'][service].setdefault('environment', {})['XOC_POLICY_STATE'] = '1'
            if 'console-' + device in selected:
                socket = 'console-' + device + '-socket'
                compose['volumes'][socket] = {}
                compose['services'][service]['volumes'].append(socket + ':/run/xoc-console')
                compose['services'][service]['environment']['XOC_CONSOLE'] = '1'
                compose['services']['platform']['volumes'].append(socket + ':/run/xoc-console-' + device + ':ro')
    if 'siem-ui' in selected:
        compose['services']['web']['environment']['XOC_SIEM_UI'] = '1'
    # ADR-0008: an entitled commercial module that requires evidence-query gets its own
    # evidence socket and credentials volumes; nothing else (and no network) can reach them.
    for identifier in selected:
        manifest = entries[identifier]["manifest"]
        if EVIDENCE not in manifest["requires"]["capabilities"]:
            continue
        if manifest["kind"] != "module" or not manifest["commercial"]:
            raise XocError("capability_not_permitted", "Only commercial modules may use evidence-query.")
        for volume, target in (evidence_volumes(identifier)):
            compose.setdefault('volumes', {})[volume] = {}
            for name, owner in owners.items():
                if owner == identifier:
                    compose['services'][name].setdefault('volumes', []).append(f'{volume}:{target}:ro')
        # C1 v0.3: the module's own writable activity log (tool receipts), read by the host collector.
        compose['volumes'][ACTIVITY_VOLUME.format(identifier)] = {}
        for name, owner in owners.items():
            if owner == identifier:
                compose['services'][name]['volumes'].append(f'{ACTIVITY_VOLUME.format(identifier)}:{ACTIVITY_TARGET}')
    holders = [i for i in selected if FACILITY in entries[i]["manifest"]["requires"]["capabilities"]]
    if holders:
        manifest = entries[holders[0]]["manifest"]
        if len(holders) > 1 or manifest["kind"] != "module" or not manifest["commercial"]:
            raise XocError("capability_not_permitted", "One commercial module may hold the facility state.")
        if 'management' not in selected:
            raise XocError("missing_capability", "The facility module needs the Core management screen.")
        for (volume, target), module_mode, platform_mode in ((FACILITY_STATE, '', ':ro'), (FACILITY_REQUESTS, ':ro', '')):
            compose.setdefault('volumes', {})[volume] = {}
            compose['services']['platform']['volumes'].append(f'{volume}:{target}{platform_mode}')
            for name, owner in owners.items():
                if owner == holders[0]:
                    compose['services'][name].setdefault('volumes', []).append(f'{volume}:{target}{module_mode}')
    if 'int' in compose['networks']:
        compose['networks']['int'] = backend_network(compose['networks']['int'])
    check_addresses(compose)
    attach_http_targets(compose, [entries[key]["manifest"] for key in selected], owners)
    services = compose["services"]
    bindings = []
    for name, service in services.items():
        if not set(service.get("depends_on", [])).issubset(services):
            raise XocError("missing_service", "A service dependency is absent from the assembled plan.")
        if service.get("ports") and all(compose["networks"][network]["internal"] for network in service["networks"]):
            raise XocError("internal_port_publish", "Docker cannot publish host ports for a service connected only to internal networks.")
        for port in service.get("ports", []):
            for previous in bindings:
                overlaps = port["host_ip"] == previous["host_ip"] or bool({port["host_ip"], previous["host_ip"]} & {"0.0.0.0", "::"})
                if port["published"] == previous["published"] and port["protocol"] == previous["protocol"] and overlaps:
                    raise XocError("port_conflict", "Selected services overlap on a published host port.")
            bindings.append(port)
    ordered(services, lambda name: services[name].get("depends_on", []), code="service_cycle")
    # Hash a portable representation; emitted Compose uses absolute build paths for execution.
    portable = copy.deepcopy(compose)
    for service in portable["services"].values():
        if "build" in service:
            service["build"]["context"] = str(Path(service["build"]["context"]).relative_to(root))
    manifests = [entries[key]['manifest'] for key in selected]
    registry = {'components': [{k: m[k] for k in ('id','title','version','provides','requires','commercial','minimum_tier')} for m in manifests],
                'panels': registrations(manifests), 'service_owners': owners,
                'targets': [dict(t, component_id=m['id']) for m in manifests for t in m.get('http_targets', [])]}
    lock = {"schema_version": "xoc.plan/0.1.0", "core_version": __version__, "preset": preset,
            "selected": selected, "requested": sorted(requested), "excluded": sorted(excluded),
            "fixtures_allowed": allow_fixtures, "experimental_allowed": allow_experimental,
            "input_sha256": dict(sorted(inputs.items())),
            "compose_sha256": hashlib.sha256(canonical(portable)).hexdigest(),
            "registry_sha256": hashlib.sha256(canonical(registry)).hexdigest()}
    lock["plan_id"] = hashlib.sha256(canonical(lock)).hexdigest()
    return {"lock": lock, "compose": compose, "registry": registry, "limitations": [
        "Offline plan only; no images built, containers started, or host resources checked.",
        "Offline plans do not resolve images; the installer records and enforces images.lock.json after building.",
        "Bootstrap is a health endpoint, not the completed Community platform.",
        *(["Security-path is experimental; run packet-path acceptance on each dedicated Ubuntu 26.04 VM."] if "security-path" in selected else []),
    ]}


def write_plan(root: Path, output: str, result):
    """Write a new local output directory only after a complete valid plan exists."""
    base = root.resolve() / ".local" / "plans"
    if not base.resolve().is_relative_to(root.resolve()):
        raise XocError("path_escape", "Plan output cannot follow a symlink outside the checkout.")
    target = within(base, output, require_file=False)
    if target == base.resolve() or target.exists():
        raise XocError("output_exists", "Choose a new named directory beneath .local/plans.")
    target.mkdir(parents=True, mode=0o700)
    try:
        (target / "compose.yaml").write_text(yaml.safe_dump(result["compose"], sort_keys=True), encoding="utf-8")
        (target / "plan.lock.json").write_text(json.dumps(result["lock"], indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except OSError:
        shutil.rmtree(target)
        raise
    return target
