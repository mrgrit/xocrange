#!/bin/bash
set -euo pipefail

# This entrypoint is for a private container network namespace only.
test -f /.dockerenv || { echo 'Container execution required' >&2; exit 2; }
case "${1:-}" in
  fw)
    ip route replace 172.29.12.0/24 via 172.29.11.2
    nft -f /etc/xoc/fw.nft
    if [[ ${XOC_POLICY_STATE:-0} == 1 ]]; then python3 -B /usr/local/lib/xoc/console/broker.py fw init; fi
    if [[ ${XOC_CONSOLE:-0} == 1 ]]; then python3 -B /usr/local/lib/xoc/console/broker.py fw & fi
    exec python3 -B /usr/local/lib/xoc/nflog.py
    ;;
  ips)
    ip route replace 172.29.10.0/24 via 172.29.11.1
    if [[ ${XOC_POLICY_STATE:-0} == 1 ]]; then python3 -B /usr/local/lib/xoc/console/broker.py ips init; fi
    python3 -B /usr/local/lib/xoc/configure-suricata.py
    suricata -T -c /run/xoc-suricata.yaml
    nft -f /etc/xoc/ips.nft
    # No queue bypass: absent/failed Suricata must not silently allow traffic.
    if [[ ${XOC_CONSOLE:-0} == 1 ]]; then python3 -B /usr/local/lib/xoc/console/broker.py ips & fi
    exec suricata -c /run/xoc-suricata.yaml -q 0 --runmode workers
    ;;
  web)
    ip route replace 172.29.10.0/24 via 172.29.12.1
    # Route setup is the only NET_ADMIN operation; Apache runs as www-data.
    exec setpriv --reuid=33 --regid=33 --clear-groups python3 -B /usr/local/lib/xoc/start-web.py
    ;;
  *) echo 'Expected fw, ips, or web role' >&2; exit 2 ;;
esac
