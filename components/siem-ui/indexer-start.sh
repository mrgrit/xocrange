#!/bin/bash
set -euo pipefail
umask 077
cp -a /usr/share/wazuh-indexer/config/. /run/xoc-indexer/
chmod -R u+rwX /run/xoc-indexer
cp -a /run/xoc-secrets/. /run/xoc-indexer/
cat /run/xoc-secrets/roles-extra.yml >> /run/xoc-indexer/opensearch-security/roles.yml
export OPENSEARCH_PATH_CONF=/run/xoc-indexer
export JAVA_HOME=/usr/share/wazuh-indexer/jdk
exec /usr/share/wazuh-indexer/bin/opensearch
