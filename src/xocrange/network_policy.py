"""Checks for the experimental routed lab; ordinary modules retain restricted privileges."""
import ipaddress

from .documents import canonical
from .errors import XocError

LAB_NETWORKS = {
    "ext": ("10.20.30.0/24", "10.20.30.254"),
    "pipe": ("10.20.31.0/24", "10.20.31.254"),
    "dmz": ("10.20.32.0/24", "10.20.32.254"),
}
# The backend network keeps the kt66 internal range. Fragments only declare it
# internal; the planner assigns this addressing. Static endpoints use the lower
# half (web .80 as in kt66) and Docker allocates dynamic ones from the upper.
BACKEND_NETWORK = ("10.20.40.0/24", "10.20.40.254", "10.20.40.128/25")
LAB_ENDPOINTS = {
    "fw": {"ext": {"ipv4_address": "10.20.30.1"}, "pipe": {"ipv4_address": "10.20.31.1"}},
    "ips": {"pipe": {"ipv4_address": "10.20.31.2"}, "dmz": {"ipv4_address": "10.20.32.1"}},
    "web": {"dmz": {"ipv4_address": "10.20.32.80"}, "int": {"ipv4_address": "10.20.40.80"}},
}


def security_role_policy(fragment):
    capabilities = {"fw": {"NET_ADMIN"}, "ips": {"NET_ADMIN", "NET_RAW"},
                    "web": {"NET_ADMIN", "SETUID", "SETGID"}}
    if set(fragment["networks"]) != {"ext", "pipe", "dmz", "int"}:
        raise XocError("security_topology", "Security path requires ext/pipe/dmz/int networks.")
    for name, (subnet, gateway) in LAB_NETWORKS.items():
        expected = {"internal": True, "driver": "bridge",
                    "driver_opts": {"com.docker.network.bridge.enable_ip_masquerade": "false"},
                    "ipam": {"config": [{"subnet": subnet, "gateway": gateway}]}}
        if fragment["networks"][name] != expected:
            raise XocError("security_topology", "Experimental transit networks must match the reviewed lab topology.")
    if fragment["networks"]["int"] != {"internal": True}:
        raise XocError("security_topology", "The backend network must remain internal.")
    for role, service in fragment["services"].items():
        expected_volume = {"fw": "fw-logs:/var/log/nftables", "ips": "ips-logs:/var/log/suricata", "web": "web-logs:/var/log/apache2"}[role]
        if service.get("volumes") != [expected_volume]:
            raise XocError("security_storage", "Each device may mount only its own log volume.")
        if set(service["cap_add"]) != capabilities[role] or service.get("ports"):
            raise XocError("security_privileges", "Device capabilities are role-specific; host publishing is not enabled in this lab.")
        if service["networks"] != LAB_ENDPOINTS[role]:
            raise XocError("security_topology", "Device endpoints must match the reviewed lab topology.")
        forwarding = "0" if role == "web" else "1"
        if service.get("sysctls") != {"net.ipv4.ip_forward": forwarding}:
            raise XocError("security_forwarding", "Only fw and ips may forward packets.")


def backend_network(declared):
    """The declared backend network with its planner-owned kt66 addressing."""
    subnet, gateway, dynamic = BACKEND_NETWORK
    return {**declared, "driver": "bridge",
            "ipam": {"config": [{"subnet": subnet, "ip_range": dynamic, "gateway": gateway}]}}


def check_addresses(compose):
    subnets, gateways, used = {}, {}, set()
    try:
        for name, definition in compose["networks"].items():
            if "ipam" not in definition:
                continue
            config = definition["ipam"]["config"][0]
            subnet = ipaddress.IPv4Network(config["subnet"], strict=True)
            gateway = ipaddress.IPv4Address(config["gateway"])
            private_blocks = [ipaddress.IPv4Network(c) for c in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
            if not any(subnet.subnet_of(block) for block in private_blocks) or not 16 <= subnet.prefixlen <= 30:
                raise ValueError()
            if gateway not in subnet or gateway in (subnet.network_address, subnet.broadcast_address):
                raise ValueError()
            if "ip_range" in config and not ipaddress.IPv4Network(config["ip_range"], strict=True).subnet_of(subnet):
                raise ValueError()
            if any(subnet.overlaps(other) for other in subnets.values()):
                raise XocError("subnet_overlap", "Selected network subnets overlap.")
            subnets[name], gateways[name] = subnet, gateway
        for service in compose["services"].values():
            if not isinstance(service["networks"], dict):
                continue
            for name, endpoint in service["networks"].items():
                if "ipv4_address" not in endpoint:
                    continue
                address = ipaddress.IPv4Address(endpoint["ipv4_address"])
                if name not in subnets or address not in subnets[name]:
                    raise ValueError()
                if address in (subnets[name].network_address, subnets[name].broadcast_address, gateways[name]):
                    raise ValueError()
                if (name, address) in used:
                    raise XocError("address_conflict", "Two services claim the same static address.")
                used.add((name, address))
    except ValueError as exc:
        # XocError inherits ValueError; preserve the specific conflict codes.
        if isinstance(exc, XocError):
            raise
        raise XocError("invalid_network_address", "Subnets, gateways, and static addresses must be private and consistent.") from exc


def attach_http_targets(compose, manifests, owners):
    targets = {}
    for manifest in manifests:
        for target in manifest.get("http_targets", []):
            name, service = target["id"], target["service"]
            if name in targets:
                raise XocError("target_conflict", "HTTP target identifiers must be unique.")
            if owners.get(service) != manifest["id"] or "int" not in compose["services"][service]["networks"]:
                raise XocError("invalid_http_target", "An HTTP target must own its backend service on the int network.")
            # Fixtures stay on the internal verification host names; reviewed
            # components are also published to learners as <id>.xoc.range.
            targets[name] = dict(target, public=True) if manifest["kind"] == "component" else target
    if targets and owners.get("web") != "security-path":
        raise XocError("missing_web_gateway", "Selected HTTP targets require the security-path gateway.")
    if owners.get("web") == "security-path":
        web = compose["services"]["web"]
        web.setdefault("environment", {})["XOC_WEB_TARGETS"] = canonical([targets[k] for k in sorted(targets)]).decode()
        web["depends_on"] = sorted(set(web.get("depends_on", [])) | {target["service"] for target in targets.values()})
