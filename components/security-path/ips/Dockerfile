FROM ubuntu:26.04
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 nftables suricata python3 python3-yaml ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY runtime/entrypoint.sh /usr/local/bin/xoc-entrypoint
COPY ips/rules.nft /etc/xoc/ips.nft
COPY ips/probe.rules /etc/xoc/probe.rules
COPY ips/configure.py /usr/local/lib/xoc/configure-suricata.py
RUN chmod 0755 /usr/local/bin/xoc-entrypoint
ENTRYPOINT ["/usr/local/bin/xoc-entrypoint", "ips"]
