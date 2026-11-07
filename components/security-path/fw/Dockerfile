FROM ubuntu:26.04
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 nftables ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY runtime/entrypoint.sh /usr/local/bin/xoc-entrypoint
COPY fw/rules.nft /etc/xoc/fw.nft
RUN chmod 0755 /usr/local/bin/xoc-entrypoint
ENTRYPOINT ["/usr/local/bin/xoc-entrypoint", "fw"]
