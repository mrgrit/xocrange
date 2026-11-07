#!/bin/sh
set -eu
for directory in alerts fts sockets rids db agentless; do
    mkdir -p "/var/ossec/queue/$directory"
done
mkdir -p /var/ossec/var/db /var/ossec/var/stats /var/ossec/var/run /var/ossec/logs/alerts /var/ossec/logs/archives /var/ossec/logs/firewall
cp -a /opt/xoc-db/. /var/ossec/var/db/
chown -R 999:999 /var/ossec/queue /var/ossec/var /var/ossec/logs
/var/ossec/bin/wazuh-db
exec /var/ossec/bin/wazuh-analysisd -f
