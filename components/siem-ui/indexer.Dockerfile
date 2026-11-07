FROM wazuh/wazuh-indexer:4.14.10
COPY --chmod=0755 indexer-start.sh /usr/local/bin/xoc-indexer
ENTRYPOINT ["/usr/local/bin/xoc-indexer"]
