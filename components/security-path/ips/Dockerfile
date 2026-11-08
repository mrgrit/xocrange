FROM ubuntu:26.04@sha256:6a06111c3b0a8600feadb270aec771dc239bf407b25625f93f44ab00e11f4d3c
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 nftables suricata python3 python3-yaml ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY runtime/console/ /usr/local/lib/xoc/console/
COPY runtime/entrypoint.sh /usr/local/bin/xoc-entrypoint
COPY ips/rules.nft /etc/xoc/ips.nft
COPY ips/probe.rules /etc/xoc/probe.rules
COPY ips/configure.py /usr/local/lib/xoc/configure-suricata.py
RUN chmod 0755 /usr/local/bin/xoc-entrypoint
ENTRYPOINT ["/usr/local/bin/xoc-entrypoint", "ips"]
