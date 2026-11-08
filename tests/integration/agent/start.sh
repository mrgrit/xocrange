#!/bin/bash
set -euo pipefail
umask 077
rm -f /run/xoc-agent-ready
install -o root -g wazuh -m 0640 /run/identity/client.keys /var/ossec/etc/client.keys
touch /var/log/xoc-agent-probe.log
mkdir -p /var/lib/xoc-probe
printf 'baseline\n' > /var/lib/xoc-probe/file
/var/ossec/bin/wazuh-control start
for attempt in $(seq 1 60); do
    if grep -F 'Analyzing file:' /var/ossec/logs/ossec.log | grep -Fq '/var/log/xoc-agent-probe.log'; then
        touch /run/xoc-agent-ready
        break
    fi
    sleep 1
done
test -f /run/xoc-agent-ready
stop() { /var/ossec/bin/wazuh-control stop; exit 0; }
trap stop TERM INT
while sleep 5 & wait $!; do
    status=$(/var/ossec/bin/wazuh-control status) || true
    grep -q '^wazuh-agentd is running' <<< "$status" || exit 1
done
