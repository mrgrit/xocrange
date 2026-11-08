FROM haproxy:3.2-alpine@sha256:96ec3c75a9264ba94e733eeacb44051ed6e7b79bb77a73c2c36f236b6423f1f0
ENTRYPOINT ["haproxy", "-W", "-db", "-f", "/run/xoc-secrets/haproxy.cfg"]
