#!/bin/bash
set -Eeuo pipefail
release=$1
runtime=$2
install -d -m 0755 /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/70-xocrange.conf <<'EOF'
[Journal]
Storage=persistent
SystemMaxUse=2G
SystemKeepFree=2G
SystemMaxFileSize=128M
MaxRetentionSec=7day
EOF
systemctl restart systemd-journald
cat > /etc/systemd/system/xocrange-log-maintenance.service <<EOF
[Unit]
Description=xOC source log rotation and acknowledged history retention
After=xocrange-core.service
[Service]
Type=oneshot
ExecStart=$runtime/bin/python $release/scripts/maintain-logs.py
UMask=0077
Environment=PYTHONDONTWRITEBYTECODE=1
EOF
cat > /etc/systemd/system/xocrange-log-maintenance.timer <<'EOF'
[Unit]
Description=Check xOC source log sizes every minute
[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
AccuracySec=5s
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now xocrange-log-maintenance.timer
