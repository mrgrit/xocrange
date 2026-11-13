#!/bin/bash
set -euo pipefail

# This entrypoint is for a private container network namespace only.
test -f /.dockerenv || { echo 'Container execution required' >&2; exit 2; }
case "${1:-}" in
  fw)
    # Filter before routing: forwarding is enabled when the namespace is created.
    nft -f /etc/xoc/fw.nft
    ip route replace 10.20.32.0/24 via 10.20.31.2
    if [[ ${XOC_POLICY_STATE:-0} == 1 ]]; then python3 -B /usr/local/lib/xoc/console/broker.py fw init; fi
    if [[ ${XOC_CONSOLE:-0} == 1 ]]; then python3 -B /usr/local/lib/xoc/console/broker.py fw & fi
    exec python3 -B /usr/local/lib/xoc/nflog.py
    ;;
  ips)
    # Load the queue table first. Forwarding is enabled when the namespace is
    # created, and setup plus the configuration test take time (longer with
    # more rules); without the table the path forwarded uninspected traffic
    # until then. Without queue bypass,
    # packets are dropped until Suricata binds queue 0.
    nft -f /etc/xoc/ips.nft
    ip route replace 10.20.30.0/24 via 10.20.31.1
    if [[ ${XOC_POLICY_STATE:-0} == 1 ]]; then python3 -B /usr/local/lib/xoc/console/broker.py ips init; fi
    python3 -B /usr/local/lib/xoc/configure-suricata.py
    suricata -T -c /run/xoc-suricata.yaml
    if [[ ${XOC_CONSOLE:-0} == 1 ]]; then python3 -B /usr/local/lib/xoc/console/broker.py ips & fi
    exec suricata -c /run/xoc-suricata.yaml -q 0 --runmode workers
    ;;
  web)
    ip route replace 10.20.30.0/24 via 10.20.32.1
    # Route setup is the only NET_ADMIN operation; Apache runs as www-data.
    exec setpriv --reuid=33 --regid=33 --clear-groups python3 -B /usr/local/lib/xoc/start-web.py
    ;;
  *) echo 'Expected fw, ips, or web role' >&2; exit 2 ;;
esac
