#!/bin/bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
/var/ossec/framework/python/bin/python3 /usr/local/lib/xoc-manager-bootstrap.py
mkdir -p /var/ossec/logs/{alerts,archives,firewall,api}
chown -R 999:999 /var/ossec/logs
/var/ossec/bin/wazuh-control start
stop() { /var/ossec/bin/wazuh-control stop; exit 0; }
trap stop TERM INT
# PID 1 fails if a required daemon dies, instead of hiding an unhealthy API.
while sleep 10 & wait $!; do
    # Upstream returns 1 when optional (disabled) daemons are stopped as well.
    status=$(/var/ossec/bin/wazuh-control status) || true
    for daemon in wazuh-apid wazuh-authd wazuh-analysisd wazuh-db wazuh-remoted wazuh-logcollector wazuh-modulesd; do
        if ! grep -q "^$daemon is running" <<< "$status"; then
            printf 'Required Manager daemon stopped: %s\n' "$daemon" >&2
            /var/ossec/bin/wazuh-control stop
            exit 1
        fi
    done
done
