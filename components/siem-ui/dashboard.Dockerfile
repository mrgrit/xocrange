FROM wazuh/wazuh-dashboard:4.14.10@sha256:0eebab19802342b841a258f56d6fa0fb085cdae08ab5eb2e45f9455c906d719a
USER root
# Upstream 4.14.10 hardcodes rejectUnauthorized:false for Manager API calls.
# Change that single reviewed call site; fail the image build on source drift.
RUN /usr/share/wazuh-dashboard/node/bin/node -e 'const fs=require("fs"),p="/usr/share/wazuh-dashboard/plugins/wazuhCore/server/services/server-api-client.js",s=fs.readFileSync(p,"utf8"),m=s.match(/rejectUnauthorized: false/g);if(!m||m.length!==1)throw Error("Unexpected Manager TLS client");fs.writeFileSync(p,s.replace("rejectUnauthorized: false","rejectUnauthorized: true"));'
ENV NODE_EXTRA_CA_CERTS=/run/xoc-secrets/manager-ca.pem
COPY wait-manager.js /usr/local/lib/xoc-wait-manager.js
COPY dashboard-start.sh /usr/local/bin/xoc-dashboard-start
RUN chmod 0755 /usr/local/bin/xoc-dashboard-start
USER 1000:1000
ENTRYPOINT ["/usr/local/bin/xoc-dashboard-start"]
