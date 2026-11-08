#!/usr/bin/env bash
# The host publishes observations; web processes never receive Docker access.
set -Eeuo pipefail
release=$1
runtime=$2
plan_name=$3
cat > /etc/systemd/system/xocrange-observer.service <<EOF
[Unit]
Description=xOC installed service state observer
After=docker.service
Requires=docker.service
RequiresMountsFor=$release /var/lib/xocrange
[Service]
Type=oneshot
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=$runtime/bin/python $release/scripts/observe-registry.py $release $plan_name
TimeoutStartSec=30
UMask=0077
NoNewPrivileges=true
EOF
cat > /etc/systemd/system/xocrange-observer.timer <<'EOF'
[Unit]
Description=Refresh xOC service observations every 15 seconds
[Timer]
OnBootSec=15
OnUnitActiveSec=15
AccuracySec=1
Unit=xocrange-observer.service
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl start xocrange-observer.service
systemctl enable --now xocrange-observer.timer
