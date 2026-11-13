#!/bin/bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
/var/ossec/framework/python/bin/python3 /usr/local/lib/xoc-manager-bootstrap.py
mkdir -p /var/ossec/logs/{alerts,archives,firewall,api}
chown -R 999:999 /var/ossec/logs
/var/ossec/bin/wazuh-control start
stop() { /var/ossec/bin/wazuh-control stop; exit 0; }
trap stop TERM INT
# Same test as upstream `wazuh-control status` (a live PID in the daemon's PID
# file), using only shell builtins. The upstream script starts about 45
# processes per call; every 10 seconds that was the largest share of the
# host's Sysmon process-creation volume.
running() {
    local file pid
    for file in /var/ossec/var/run/"$1"-*.pid; do
        [[ -f $file ]] || continue
        pid=
        read -r pid < "$file" || [[ -n $pid ]] || continue
        [[ $pid =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null && return 0
    done
    return 1
}
# `read -t` on a FIFO nobody writes waits without starting a `sleep` process
# each round, and a trapped TERM still interrupts it immediately.
wait_fifo=$(mktemp -u /tmp/xoc-wait.XXXXXX)
mkfifo -m 0600 "$wait_fifo"
exec 3<>"$wait_fifo"
rm -f "$wait_fifo"
# PID 1 fails if a required daemon dies, instead of hiding an unhealthy API.
while true; do
    read -r -t 10 -u 3 _ || true
    for daemon in wazuh-apid wazuh-authd wazuh-analysisd wazuh-db wazuh-remoted wazuh-logcollector wazuh-modulesd; do
        if ! running "$daemon"; then
            printf 'Required Manager daemon stopped: %s\n' "$daemon" >&2
            /var/ossec/bin/wazuh-control stop
            exit 1
        fi
    done
done
