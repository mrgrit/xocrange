#!/usr/bin/env bash
# Called by install.sh only after dedicated VM checks and SIEM module selection.
set -Eeuo pipefail
umask 077
release=$1
runtime=$2
plan_name=$3
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
apt_options=(-o DPkg::Lock::Timeout=120 -o Acquire::Retries=3)
install -d -m 0700 /etc/xocrange /var/lib/xocrange/siem /var/lib/xocrange/osquery /var/log/xocrange/osquery
install -d -m 0755 /etc/apt/keyrings
touch /var/lib/xocrange/telemetry-owned
if ! dpkg-query -W -f='${Status}' sysmonforlinux 2>/dev/null | grep -qx 'install ok installed'; then
    curl -fsSL --retry 3 --connect-timeout 15 --max-time 120 \
        https://packages.microsoft.com/config/ubuntu/26.04/packages-microsoft-prod.deb \
        -o /var/lib/xocrange/packages-microsoft-prod.deb
    dpkg -i /var/lib/xocrange/packages-microsoft-prod.deb
fi
if ! dpkg-query -W -f='${Status}' osquery 2>/dev/null | grep -qx 'install ok installed'; then
    curl -fsSL --retry 3 --connect-timeout 15 --max-time 120 https://pkg.osquery.io/deb/pubkey.gpg \
        -o /etc/apt/keyrings/xocrange-osquery.asc
    printf '%s\n' 'deb [arch=amd64 signed-by=/etc/apt/keyrings/xocrange-osquery.asc] https://pkg.osquery.io/deb deb main' \
        > /etc/apt/sources.list.d/xocrange-osquery.list
fi
apt_retry "${apt_options[@]}" update
missing=()
for package in auditd osquery sysmonforlinux; do
    if [[ $(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true) != 'install ok installed' ]]; then missing+=("$package"); fi
done
if ((${#missing[@]})); then apt_retry "${apt_options[@]}" install -y --no-install-recommends "${missing[@]}"; fi
install -m 0600 "$release/components/siem/osquery.conf" /etc/xocrange/osquery.conf
install -m 0600 "$release/components/siem/sysmon.xml" /etc/xocrange/sysmon.xml
cat > /etc/systemd/system/xocrange-osquery.service <<'EOF'
[Unit]
Description=xOC Core osquery metadata schedule
After=network.target
[Service]
ExecStart=/opt/osquery/bin/osqueryd --config_path=/etc/xocrange/osquery.conf --pidfile=/var/lib/xocrange/osquery/osquery.pidfile --database_path=/var/lib/xocrange/osquery/osquery.db --logger_plugin=filesystem --logger_stderr=false
Restart=on-failure
UMask=0077
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now xocrange-osquery.service
systemctl restart xocrange-osquery.service
install -d -m 2755 /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal
journalctl --flush
if systemctl cat sysmon.service >/dev/null 2>&1; then
    systemctl enable --now sysmon.service
    sysmon -c /etc/xocrange/sysmon.xml
else
    sysmon -accepteula -i /etc/xocrange/sysmon.xml
fi
systemctl enable sysmon.service
systemctl enable auditd.service
# On Ubuntu 26.04 auditd Wants a non-persistent audit-rules oneshot. Starting
# an already active auditd can re-run that loader concurrently with our updates.
if ! systemctl is-active --quiet auditd.service; then systemctl start auditd.service; fi
for ((attempt=0; attempt<30; attempt++)); do
    audit_job=$(systemctl show audit-rules.service --property=Job --value 2>/dev/null || true)
    [[ -z $audit_job || $audit_job == 0 ]] && break
    sleep 1
done
[[ -z $audit_job || $audit_job == 0 ]] || { printf 'Audit rule loader did not finish\n' >&2; exit 2; }
# Add only xOC's rules; never flush the host audit rules or change immutable mode.
python3 "$release/scripts/configure-audit.py" "$release/components/siem/audit.rules" --output /etc/audit/rules.d/70-xocrange.rules
cat > /etc/systemd/system/xocrange-collector.service <<EOF
[Unit]
Description=xOC Core durable collection and Wazuh decoding
Requires=xocrange-core.service
After=xocrange-core.service auditd.service sysmon.service xocrange-osquery.service
PartOf=xocrange-core.service
[Service]
ExecStart=$runtime/bin/xoc --root $release siem collect --plan $plan_name
Restart=on-failure
RestartSec=5
UMask=0077
Environment=PYTHONDONTWRITEBYTECODE=1
[Install]
WantedBy=xocrange-core.service
EOF
systemctl daemon-reload
systemctl enable --now xocrange-collector.service
