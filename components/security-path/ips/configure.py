"""Adapt the distribution's configuration without rewriting installed files."""
from pathlib import Path
import yaml


def configure(original):
    original.setdefault("vars", {}).setdefault("address-groups", {})["HOME_NET"] = "[172.29.12.0/24]"
    original.setdefault("stream", {})["inline"] = True
    original["nfq"] = {"mode": "accept", "fail-open": False}
    original["default-log-dir"] = "/var/log/suricata"
    original["default-rule-path"] = "/etc/xoc"
    original["rule-files"] = ["probe.rules"]
    original["stats"] = {"enabled": False}
    original["unix-command"] = {"enabled": False}
    original["pid-file"] = "/run/suricata.pid"
    original.pop("run-as", None)
    original["outputs"] = [{"eve-log": {"enabled": True, "filetype": "regular", "filename": "eve.json",
                                       "types": [{"alert": {"payload": False, "packet": False, "metadata": False}}]}}]
    original["logging"] = {"default-log-level": "notice", "outputs": [{"console": {"enabled": True}}]}
    return original


if __name__ == "__main__":
    source = yaml.safe_load(Path("/etc/suricata/suricata.yaml").read_text())
    Path("/run/xoc-suricata.yaml").write_text(yaml.safe_dump(configure(source), sort_keys=False))
