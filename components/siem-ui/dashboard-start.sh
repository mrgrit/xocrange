#!/bin/sh
set -eu
/usr/share/wazuh-dashboard/node/bin/node /usr/local/lib/xoc-wait-manager.js
exec /usr/share/wazuh-dashboard/bin/opensearch-dashboards --config /run/xoc-secrets/dashboard.yml
