"""Adapt the distribution's configuration without rewriting installed files."""
from pathlib import Path
import os
import yaml


def configure(original):
    original.setdefault("vars", {}).setdefault("address-groups", {})["HOME_NET"] = "[10.20.32.0/24,10.20.70.0/24]"
    original.setdefault("stream", {})["inline"] = True
    original["nfq"] = {"mode": "accept", "fail-open": False}
    original["default-log-dir"] = "/var/log/suricata"
    original["default-rule-path"] = "/etc/xoc"
    original["rule-files"] = ["probe.rules"] + (["/var/lib/xoc-console/current.conf"] if os.environ.get("XOC_POLICY_STATE") == "1" else [])
    original["stats"] = {"enabled": True, "interval": 8}
    original["unix-command"] = {"enabled": True, "filename": "/run/suricata-command.socket"}
    original["pid-file"] = "/run/suricata.pid"
    original.pop("run-as", None)
    original["outputs"] = [{"eve-log": {"enabled": True, "filetype": "regular", "filename": "eve.json",
                                       "types": [{"alert": {"payload": False, "packet": False, "metadata": False}}]}}]
    original["logging"] = {"default-log-level": "notice", "outputs": [{"console": {"enabled": True}}]}
    return original


def render(original):
    # Suricata's loader requires an explicit YAML 1.1 document header.
    return yaml.safe_dump(configure(original), sort_keys=False, version=(1, 1), explicit_start=True)


if __name__ == "__main__":
    source = yaml.safe_load(Path("/etc/suricata/suricata.yaml").read_text())
    Path("/run/xoc-suricata.yaml").write_text(render(source))
