FROM opensearchproject/opensearch-dashboards:2.19.6
ENTRYPOINT ["/usr/share/opensearch-dashboards/bin/opensearch-dashboards", "--config", "/run/xoc-secrets/dashboard.yml"]
