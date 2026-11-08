FROM haproxy:3.2-alpine
ENTRYPOINT ["haproxy", "-W", "-db", "-f", "/run/xoc-secrets/haproxy.cfg"]
