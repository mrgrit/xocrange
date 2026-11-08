FROM wazuh/wazuh-indexer:4.14.10@sha256:e56f85ed9e79f113c0f2d2a7965171cd8e063262ec88e110086acdb1f69f2240
COPY --chmod=0755 indexer-start.sh /usr/local/bin/xoc-indexer
ENTRYPOINT ["/usr/local/bin/xoc-indexer"]
