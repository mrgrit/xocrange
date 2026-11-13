"""Explicit execution and packet-path checks for a dedicated Ubuntu 26.04 VM."""
from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import subprocess
import time

from .documents import json_document, read_bytes, within, yaml_document
from .errors import XocError
from .events import Context, normalize
from .network_policy import LAB_NETWORKS
from .planner import plan


class Docker:
    def __init__(self, compose_path, project):
        self.base = ["docker", "--context", "default"]
        self.compose = self.base + ["compose", "--project-name", project, "-f", str(compose_path)]
        from .image_lock import checked
        locked = checked(Path(compose_path).parent)
        if locked:
            self.compose += ['-f', str(locked)]

    def run(self, args, *, compose=False, timeout=60):
        try:
            result = subprocess.run((self.compose if compose else self.base) + list(args),
                                    capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise XocError("docker_unavailable", "Docker is unavailable or the requested operation timed out.") from exc
        if result.returncode:
            raise XocError("docker_failed", "Docker operation failed; inspect the dedicated lab's build/container logs.")
        return result.stdout


def checked_plan(root, name, *, entitlement_action='stop'):
    # Structural/source validation is independent of paid grants. Start paths
    # authorize explicitly; stopped/expired extensions cannot disable Core reads.
    directory = within(root, f".local/plans/{name}", require_file=False)
    lock = json_document(read_bytes(directory / "plan.lock.json"))
    try:
        expected = plan(root, preset=lock["preset"], include=lock["requested"], without=lock["excluded"],
                        allow_fixtures=lock["fixtures_allowed"], allow_experimental=lock["experimental_allowed"],
                        entitlement_action=entitlement_action)
        if lock != expected["lock"] or "security-path" not in lock["selected"]:
            raise XocError("stale_plan", "Regenerate the security-path plan from the current source inputs.")
        if yaml_document(directory / "compose.yaml") != expected["compose"]:
            raise XocError("modified_compose", "Generated Compose differs from the validated plan.")
    except (KeyError, TypeError) as exc:
        raise XocError("invalid_plan", "Expected an intact installation plan and lock.") from exc
    return directory, expected


def host_check(engine, project):
    checks = {}
    try:
        release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
        checks["ubuntu_26_04"] = release.get("ID", "").strip('"') == "ubuntu" and release.get("VERSION_ID", "").strip('"') == "26.04"
        vm = subprocess.run(["systemd-detect-virt", "--vm"], capture_output=True, text=True, timeout=5)
        checks["virtual_machine"] = vm.returncode == 0
        bridge = Path("/proc/sys/net/bridge/bridge-nf-call-iptables")
        checks["bridge_netfilter_disabled"] = bridge.is_file() and bridge.read_text().strip() == "0"
        checks["nfqueue_module_loaded"] = Path("/sys/module/nfnetlink_queue").is_dir()
        endpoint = engine.run(["context", "inspect", "default", "--format", "{{.Endpoints.docker.Host}}"])
        checks["local_daemon"] = endpoint.strip() in ("unix:///var/run/docker.sock", "unix:///run/docker.sock")
        if not checks["local_daemon"]:
            return {"status": "blocked", "checks": checks}
        info = json.loads(engine.run(["info", "--format", "{{json .}}"])); checks["linux_daemon"] = info.get("OSType") == "linux"
        checks["rootful_daemon"] = not any("rootless" in option for option in info.get("SecurityOptions", []))
        engine.run(["compose", "version"])
        checks["compose_plugin"] = True
        rows = [json.loads(line) for line in engine.run(["ps", "--all", "--format", "{{json .}}"] ).splitlines() if line]
        checks["dedicated_daemon"] = all(f"com.docker.compose.project={project}" in row.get("Labels", "").split(",") for row in rows)
        network_ids = engine.run(["network", "ls", "--quiet"]).split()
        networks = json.loads(engine.run(["network", "inspect", *network_ids])) if network_ids else []
        desired = [ipaddress.IPv4Network(pair[0]) for pair in LAB_NETWORKS.values()]
        owned, overlaps = set(), []
        for network in networks:
            is_owned = (network.get("Labels") or {}).get("com.docker.compose.project") == project
            for config in ((network.get("IPAM") or {}).get("Config") or []):
                subnet = config.get("Subnet", "")
                if ":" in subnet or not subnet:
                    continue
                net = ipaddress.IPv4Network(subnet)
                if is_owned:
                    owned.add(str(net))
                elif any(net.overlaps(wanted) for wanted in desired):
                    overlaps.append(str(net))
        checks["no_docker_subnet_overlap"] = not overlaps
        routes = subprocess.run(["ip", "-j", "-4", "route", "show", "table", "all"], capture_output=True, text=True, timeout=5)
        if routes.returncode:
            checks["no_host_route_overlap"] = False
        else:
            overlap = False
            for route in json.loads(routes.stdout):
                destination = route.get("dst", "default")
                if destination == "default" or route.get("type") in ("local", "broadcast"):
                    continue
                net = ipaddress.IPv4Network(destination, strict=False)
                if str(net) not in owned and any(net.overlaps(wanted) for wanted in desired):
                    overlap = True
            checks["no_host_route_overlap"] = not overlap
    except (OSError, ValueError, subprocess.TimeoutExpired, XocError):
        checks["host_inspection_complete"] = False
    return {"status": "ready" if checks and all(checks.values()) else "blocked", "checks": checks,
            "scope": "Dedicated VM prerequisites only; packet-path acceptance requires lab verify."}


def records(text):
    """Read JSON objects separated by whitespace, including multiline ModSecurity JSON."""
    decoder, offset = json.JSONDecoder(), 0
    while offset < len(text):
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset == len(text):
            break
        _, end = decoder.raw_decode(text, offset)
        yield text[offset:end].encode()
        offset = end


def verify(engine):
    checks, evidence = {}, {}
    log_sources = [("suricata", "ips", "0:0", "/var/log/suricata/eve.json"),
                   ("modsecurity", "web", "33:33", "/var/log/apache2/modsec_audit.json")]

    def probe(*options):
        return json.loads(engine.run(["exec", "-T", "lab-client", "python", "-B", "/app/probe.py", *options], compose=True))

    def counter(service, name):
        table = "xoc_fw" if service == "fw" else "xoc_ips"
        value = json.loads(engine.run(["exec", "-T", service, "nft", "-j", "list", "counter", "inet", table, name], compose=True))
        return next(item["counter"]["packets"] for item in value["nftables"] if "counter" in item)

    for _ in range(30):
        try:
            if probe().get("status") == 200:
                break
        except XocError:
            pass
        time.sleep(2)
    health_reader = "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3).read(16384).decode())"
    # The landing path can answer before the platform's own listener does,
    # e.g. right after a restore restarts every container.
    for attempt in range(30):
        try:
            health = json.loads(engine.run(["exec", "-T", "platform", "python", "-B", "-c", health_reader], compose=True))
            break
        except XocError:
            if attempt == 29:
                raise
            time.sleep(2)
    checks["platform_health"] = isinstance(health, dict) and health.get("service") == "xocrange-core" and health.get("status") == "bootstrap"
    # Dropped DAC capabilities also constrain uid 0; use each log's actual owner.
    offsets = {source: int(engine.run(["exec", "-T", "--user", user, service, "wc", "-c", path], compose=True).split()[0])
               for source, service, user, path in log_sources}
    before_fw, before_ips = counter("fw", "forwarded_web"), counter("ips", "inspected")
    landing = probe(); target = probe("--host", "sample.xoc.test")
    checks["landing_available"] = landing.get("status") == 200
    checks["selected_target_available"] = target.get("status") == 200
    body = json.loads(target["body"]) if target.get("status") == 200 else {}
    checks["source_ip_and_forwarded_header"] = body.get("target") == "sample" and body.get("forwarded_for") == "172.29.10.10"
    checks["fw_on_packet_path"] = counter("fw", "forwarded_web") > before_fw
    checks["ips_on_packet_path"] = counter("ips", "inspected") > before_ips
    denied_before = counter("fw", "blocked_input")
    checks["fw_denies_other_port"] = probe("--port", "8081").get("status") is None and counter("fw", "blocked_input") > denied_before
    checks["no_direct_waf_bypass"] = probe("--address", "172.29.12.80").get("status") is None
    target_container = engine.run(["ps", "--quiet", "lab-target"], compose=True).strip()
    target_info = json.loads(engine.run(["inspect", target_container]))[0]
    target_ip = next(value["IPAddress"] for key, value in target_info["NetworkSettings"]["Networks"].items() if key.endswith("_int"))
    checks["no_direct_backend_bypass"] = probe("--address", target_ip).get("status") is None
    checks["waf_marker_blocked"] = probe("--marker", "waf-block").get("status") == 403
    checks["ips_marker_blocked"] = probe("--marker", "ips-block").get("status") is None
    # Let buffered audit records reach the bounded tmpfs logs.
    time.sleep(2)
    observed = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    for source, service, user, path in log_sources:
        # Only this run's appended records count; old alerts must not prove a new block.
        reader = ("import os,sys; f=open(sys.argv[1],'rb'); offset=int(sys.argv[2]); "
                  "assert os.fstat(f.fileno()).st_size>=offset; f.seek(offset); "
                  "data=f.read(1048577); assert len(data)<=1048576; sys.stdout.buffer.write(data)")
        raw = engine.run(["exec", "-T", "--user", user, service, "python3", "-B", "-c", reader, path, str(offsets[source])], compose=True)
        normalized = []
        for index, record in enumerate(records(raw)):
            if source == "suricata" and json.loads(record).get("event_type") != "alert":
                continue
            ctx = Context("community", "security-lab", service, f"lab://{observed}/{source}/{index}", observed)
            normalized.extend(normalize(source, record, ctx))
        evidence[source] = normalized
    checks["ips_c1_block_evidence"] = any(event.get("rule", {}).get("id") == "1000001" and event["event"]["outcome"] == "blocked"
                                          and event.get("network", {}).get("source", {}).get("ip") == "172.29.10.10"
                                          for event in evidence["suricata"])
    checks["waf_c1_block_evidence"] = any(event.get("rule", {}).get("id") == "1000002" and event["event"]["outcome"] == "blocked"
                                          and event.get("network", {}).get("source", {}).get("ip") == "172.29.10.10"
                                          for event in evidence["modsecurity"])
    try:
        engine.run(["stop", "ips"], compose=True)
        checks["ips_unavailable_blocks_path"] = probe().get("status") is None
    finally:
        engine.run(["start", "ips"], compose=True)
    restored = False
    for _ in range(15):
        if probe().get("status") == 200:
            restored = True
            break
        time.sleep(2)
    checks["path_recovers_after_ips_restart"] = restored
    return {"status": "passed" if all(checks.values()) else "failed", "checks": checks, "c1_evidence": evidence}


def run_lab(root, name, action, isolated_vm=False):
    directory, result = checked_plan(root, name, entitlement_action='start' if action in ('up', 'start') else 'stop')
    project = result["compose"]["name"]
    engine = Docker(directory / "compose.yaml", project)
    if action != "check" and not isolated_vm:
        raise XocError("isolated_vm_required", "Execution requires --isolated-vm on the dedicated test VM.")
    report = host_check(engine, project)
    if action == "down" and all(report["checks"].get(key) for key in (
            "ubuntu_26_04", "virtual_machine", "local_daemon", "linux_daemon", "rootful_daemon", "dedicated_daemon")):
        # Cleanup must still work if a restart changed bridge/NFQUEUE prerequisites.
        engine.run(["down"], compose=True, timeout=120)
        return {"status": "stopped", "project": project}
    if action == "check" or report["status"] != "ready":
        return report
    if action in ("up", "start", "resume"):
        if action == 'up' and (directory/'images.lock.json').exists():
            action = 'start'
        options = ["up", "--build", "--detach"] if action == "up" else ["up", "--detach", "--no-build", "--pull", "never"]
        blocked = {}
        extra = []
        if action == 'resume':
            from .entitlements import authorize
            from .planner import catalog
            entries = catalog(root, allow_fixtures=result['lock']['fixtures_allowed'])
            for identifier in result['lock']['selected']:
                try:
                    authorize(root, entries[identifier]['manifest'], 'start')
                except XocError as exc:
                    blocked[identifier] = exc.code
            changed = True
            while changed:
                changed = False
                for identifier in result['lock']['selected']:
                    if identifier not in blocked and set(entries[identifier]['manifest']['requires']['components']) & set(blocked):
                        blocked[identifier] = 'entitlement_dependency'; changed = True
            denied = {service for service, owner in result['registry']['service_owners'].items() if owner in blocked}
            while True:
                more = {name for name, definition in result['compose']['services'].items() if set(definition.get('depends_on', [])) & denied}
                if more <= denied: break
                denied |= more
            if denied:
                engine.run(['stop', *sorted(denied)], compose=True, timeout=120)
                extra = ['--no-deps', *sorted(set(result['compose']['services'])-denied)]
        engine.run(options + ["--remove-orphans", *extra], compose=True, timeout=1800 if action == "up" else 120)
        return {"status": "started", "project": project, "acceptance": "not-yet-verified", 'blocked_modules':blocked}
    if "fixture-security-probe" not in result["lock"]["selected"]:
        raise XocError("probe_missing", "lab verify requires the explicit fixture-security-probe selection.")
    try:
        report = verify(engine)
    except (ValueError, KeyError, StopIteration) as exc:
        if isinstance(exc, XocError):
            raise
        raise XocError("invalid_lab_evidence", "Lab evidence was missing or did not match the expected data format.") from exc
    report["plan_id"] = result["lock"]["plan_id"]
    evidence_name = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".json"
    output = within(root, ".local/lab-results/" + evidence_name, require_file=False)
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    output.write_text(json.dumps(report, indent=2) + "\n"); output.chmod(0o600)
    return {"status": report["status"], "checks": report["checks"], "report": str(output)}
