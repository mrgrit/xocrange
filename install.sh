#!/usr/bin/env bash
# xOC Range Core: bare Ubuntu -> dependencies -> selected services -> acceptance.
set -Eeuo pipefail
umask 077

usage() {
    cat <<'EOF'
Usage: sudo bash install.sh [options]

Install the current experimental Core security path on a dedicated Ubuntu 26.04
amd64 VM. Docker, Python, network prerequisites, images and verification are automatic.
The current default includes platform, fw, IPS, WAF and harmless acceptance probes.
Common management authentication, SIEM collection, eight decoders and HTTPS dashboards are included.
--without siem omits SIEM; --without siem-ui keeps local collection without SIEM UI.
Common HTTPS management remains available with either option.
FW, IPS and WAF consoles are included; --without console-fw (or console-ips/console-waf)
omits its management UI while preserving existing device policy.
--without portal, --without noc and --without academy-reader omit each workspace independently.
Portal, NOC 2F and bundled guides are included; the complete Community release remains under development.

  --include ID       Add an implemented module (repeatable)
  --without ID       Exclude an optional module (repeatable)
  --data-dir PATH    Docker AND containerd data directory; no disk formatting
                    Default: /var/lib/xocrange/data
  --ref COMMIT       Download an exact 40-character Git commit instead of local source
  --public-host HOST IPv4 address or DNS name for HTTPS (default: host's route IP)
  --dry-run          Describe operations without installing or accessing the network
  --help            Show this help

Running this development installer selects the experimental security-path profile.
An existing unrelated Docker/containerd installation is never removed or migrated.
EOF
}

fail() { printf 'xOC install failed: %s\n' "$*" >&2; exit 2; }
stage() { current_stage=$1; printf '\n[xOC] %s\n' "$current_stage"; }
need_value() { [[ $# -ge 2 && -n $2 && $2 != --* ]] || fail "Missing value for $1"; }
selection=()
siem_selection=(--include siem)
ui_selection=(--include siem-ui)
management_selection=(--include management)
optional_selection=()
public_host=
data_directory=/var/lib/xocrange/data
source_ref=
dry_run=false
while (($#)); do
    case "$1" in
        --include|--without)
            need_value "$@"
            [[ $2 =~ ^[a-z][a-z0-9-]{0,63}$ ]] || fail 'Invalid module ID'
            selection+=("$1" "$2"); shift 2 ;;
        --data-dir) need_value "$@"; data_directory=$2; shift 2 ;;
        --public-host) need_value "$@"; public_host=$2; shift 2 ;;
        --ref)
            need_value "$@"
            [[ $2 =~ ^[0-9a-f]{40}$ ]] || fail '--ref requires a full Git commit hash'
            source_ref=$2; shift 2 ;;
        --dry-run) dry_run=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *) fail "Unknown option: $1" ;;
    esac
done
for ((i=0; i<${#selection[@]}; i++)); do
    if [[ ${selection[i]} == --without && ${selection[i+1]:-} == siem ]]; then siem_selection=(); ui_selection=(); fi
    if [[ ${selection[i]} == --without && ${selection[i+1]:-} == siem-ui ]]; then ui_selection=(); fi
done
for console_id in console-fw console-ips console-waf portal noc academy-reader; do
    console_excluded=false
    for ((i=0; i<${#selection[@]}; i++)); do
        if [[ ${selection[i]} == --without && ${selection[i+1]:-} == "$console_id" ]]; then console_excluded=true; fi
    done
    if ! $console_excluded; then optional_selection+=(--include "$console_id"); fi
done
[[ $data_directory =~ ^/[A-Za-z0-9_/-]+$ && $data_directory != / ]] || fail 'Invalid data directory'
[[ -z $public_host || $public_host =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$ ]] || fail 'Invalid public hostname'
if $dry_run; then
    usage
    printf '\nData directory: %s\n' "$data_directory"
    printf 'Selection arguments:'; if ((${#selection[@]})); then printf ' %q' "${selection[@]}"; fi; printf '\n'
    printf '%s\n' 'Order: VM preflight -> base packages -> source snapshot -> module plan -> Docker' \
        '       -> storage -> kernel/network prerequisites -> build -> start -> acceptance -> boot service' \
        'No changes performed. Dependency resolution and VM acceptance have not run.'
    exit 0
fi
(( EUID == 0 )) || fail 'Run this single installer with sudo: sudo bash install.sh'
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a PYTHONDONTWRITEBYTECODE=1 PIP_DISABLE_PIP_VERSION_CHECK=1
unset DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG COMPOSE_FILE COMPOSE_PROJECT_NAME PYTHONPATH PYTHONHOME

# Check before any package or host mutation. The existing kt66 host is not a target.
source /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 26.04 ]] || fail 'Ubuntu Server 26.04 LTS is required'
[[ $(dpkg --print-architecture) == amd64 ]] || fail 'The current installation target is amd64'
systemd-detect-virt --vm >/dev/null || fail 'Use a dedicated VM for this experimental release'
[[ -d /run/systemd/system ]] || fail 'systemd is required'
awk '/MemTotal/ {exit ($2 < 3500000)}' /proc/meminfo || fail 'At least 4 GB RAM is needed for this profile'
if ((${#ui_selection[@]})); then
    awk '/MemTotal/ {exit ($2 < 7500000)}' /proc/meminfo || fail 'SIEM dashboards require at least 8 GB RAM'
fi
[[ $(nproc) -ge 2 ]] || fail 'At least 2 vCPUs are needed for this profile'
exec 9>/run/lock/xocrange-install.lock
flock -n 9 || fail 'Another xOC installation is in progress'

state=/var/lib/xocrange
prefix=/opt/xocrange
install -d -m 0700 "$state" /var/log/xocrange
install -d -m 0755 "$prefix"
run_id=$(date -u +%Y%m%dT%H%M%S)-$$
log=/var/log/xocrange/install-$run_id.log
exec > >(tee -a "$log") 2>&1
current_stage=preflight
on_exit() {
    code=$?
    if ((code)); then
        printf '{"status":"failed","stage":"%s","exit_code":%s,"log":"%s"}\n' \
            "$current_stage" "$code" "$log" > "$state/last-install.json"
        printf '\nInstallation did not complete. Stage: %s. Log: %s\n' "$current_stage" "$log" >&2
    fi
}
trap on_exit EXIT

stage dedicated-host-check
check_containers() {
    owners=$(docker --context default ps -a --format '{{.Label "com.docker.compose.project"}}:{{.ID}}')
    if [[ -n $owners ]]; then
        while IFS= read -r owner; do
            [[ $owner == xoc-core-security-path:* ]] || fail 'Unrelated containers exist on this host'
        done <<< "$owners"
    fi
}
if command -v docker >/dev/null; then
    [[ -f $state/installer-owned ]] || fail 'Existing Docker is not owned by this installer'
    [[ $(docker --context default context inspect default --format '{{.Endpoints.docker.Host}}') == unix:///var/run/docker.sock ]] \
        || fail 'Expected the local Docker daemon'
    if docker --context default info >/dev/null 2>&1; then
        check_containers
    else
        printf 'Resuming the installer-owned runtime after an interrupted installation.\n'
    fi
fi
for package in docker.io docker-compose docker-compose-v2 docker-buildx podman-docker containerd runc; do
    if [[ $(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true) == 'install ok installed' ]]; then
        fail "Existing conflicting package: $package; refusing automatic removal"
    fi
done
if [[ ! -f $state/installer-owned ]]; then
    for directory in /var/lib/docker /var/lib/containerd; do
        if [[ -d $directory && -n $(find "$directory" -mindepth 1 -maxdepth 1 -print -quit) ]]; then
            fail "Existing runtime data found at $directory"
        fi
    done
fi
printf 'xocrange installer v1\n' > "$state/installer-owned"

stage base-packages
apt_options=(-o DPkg::Lock::Timeout=120 -o Acquire::Retries=3 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30)
apt-get "${apt_options[@]}" update
apt-get "${apt_options[@]}" install -y --no-install-recommends ca-certificates curl git python3 python3-venv iproute2 kmod openssl

stage source-snapshot
source_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
if [[ -n $source_ref || ! -f $source_directory/src/xocrange/planner.py ]]; then
    downloaded=$state/download-$run_id
    git init -q "$downloaded"
    git -C "$downloaded" remote add origin https://github.com/mrgrit/xocrange.git
    git -C "$downloaded" fetch --depth 1 origin "${source_ref:-main}"
    git -C "$downloaded" checkout -q --detach FETCH_HEAD
    source_directory=$downloaded
fi
release=$(python3 "$source_directory/scripts/install-support.py" snapshot "$source_directory" "$prefix/releases")
runtime=$prefix/venvs/$(basename "$release")
[[ -x $runtime/bin/python ]] || python3 -m venv "$runtime"
"$runtime/bin/python" -m pip install "$release"
xoc=("$runtime/bin/xoc" --root "$release")

stage module-plan
plan_json=$state/plan-$run_id.json
"${xoc[@]}" plan --preset security-path --allow-experimental --allow-fixtures \
    --include fixture-security-probe "${siem_selection[@]}" "${ui_selection[@]}" "${management_selection[@]}" "${optional_selection[@]}" "${selection[@]}" > "$plan_json"
plan_name=install-$("$runtime/bin/python" -c 'import json,sys; print(json.load(open(sys.argv[1]))["lock"]["plan_id"])' "$plan_json")
if [[ ! -d $release/.local/plans/$plan_name ]]; then
    "${xoc[@]}" plan --preset security-path --allow-experimental --allow-fixtures \
        --include fixture-security-probe "${siem_selection[@]}" "${ui_selection[@]}" "${management_selection[@]}" "${optional_selection[@]}" "${selection[@]}" --output "$plan_name" > "$plan_json"
fi
# Prevent exclusion of a required acceptance service, before any Docker installation.
"$runtime/bin/python" - "$release" "$plan_name" <<'PY'
from pathlib import Path
import sys
from xocrange.lab import checked_plan
_, result = checked_plan(Path(sys.argv[1]), sys.argv[2])
assert {'platform', 'security-path', 'fixture-security-probe'} <= set(result['lock']['selected'])
PY
compose=(docker --context default compose --project-name xoc-core-security-path -f "$release/.local/plans/$plan_name/compose.yaml")

stage docker-packages
if ! command -v docker >/dev/null; then
    install -d -m 0755 /etc/apt/keyrings
    curl --fail --silent --show-error --location --retry 3 --connect-timeout 15 --max-time 120 \
        https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/xocrange-docker.asc
    chmod 0644 /etc/apt/keyrings/xocrange-docker.asc
    cat > /etc/apt/sources.list.d/xocrange-docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: ${UBUNTU_CODENAME:-$VERSION_CODENAME}
Components: stable
Architectures: amd64
Signed-By: /etc/apt/keyrings/xocrange-docker.asc
EOF
    apt-get "${apt_options[@]}" update
fi
missing_packages=()
for package in docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; do
    if [[ $(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true) != 'install ok installed' ]]; then
        missing_packages+=("$package")
    fi
done
if ((${#missing_packages[@]})); then
    apt-get "${apt_options[@]}" install -y --no-install-recommends "${missing_packages[@]}"
fi
docker --context default compose version
systemctl start containerd.service docker.service
check_containers

stage storage
if [[ -f $state/storage-configured ]]; then
    [[ $(cat "$state/storage-configured") == "$data_directory" ]] || fail 'Changing the data directory needs a separate data migration'
else
    [[ -z $(docker --context default ps -aq) && -z $(docker --context default image ls -q) && -z $(docker --context default volume ls -q) ]] \
        || fail 'Runtime data appeared before storage setup; refusing automatic relocation'
    python3 "$release/scripts/install-support.py" storage "$data_directory" "$state/storage-candidate"
    install -d -m 0700 "$state/original-config" "$data_directory"
    if [[ ! -f $state/original-config/saved ]]; then
        [[ ! -f /etc/docker/daemon.json ]] || cp -p /etc/docker/daemon.json "$state/original-config/daemon.json"
        [[ ! -f /etc/containerd/config.toml ]] || cp -p /etc/containerd/config.toml "$state/original-config/config.toml"
        touch "$state/original-config/saved"
    fi
    systemctl stop docker.service docker.socket containerd.service
    install -d -m 0755 /etc/docker /etc/containerd
    install -m 0644 "$state/storage-candidate/daemon.json" /etc/docker/daemon.json
    install -m 0644 "$state/storage-candidate/config.toml" /etc/containerd/config.toml
    dockerd --validate --config-file=/etc/docker/daemon.json
    containerd --config /etc/containerd/config.toml config dump >/dev/null
    printf '%s\n' "$data_directory" > "$state/storage-configured"
fi
[[ $(df --output=avail -BG "$data_directory" | tail -1 | tr -dc '0-9') -ge 20 ]] || fail 'At least 20 GB free data space is required'
systemctl enable --now containerd.service docker.service

stage network-prerequisites
"$runtime/bin/python" - "$release" "$plan_name" <<'PY'
from pathlib import Path
import json,sys
from xocrange.lab import Docker,checked_plan,host_check
directory,result = checked_plan(Path(sys.argv[1]),sys.argv[2])
report = host_check(Docker(directory/'compose.yaml',result['compose']['name']),result['compose']['name'])
pending = {'bridge_netfilter_disabled','nfqueue_module_loaded'}
failures = [key for key,value in report['checks'].items() if not value and key not in pending]
if failures:
    print(json.dumps(report,indent=2)); raise SystemExit(2)
PY
modprobe -a br_netfilter nfnetlink_queue nfnetlink_log
[[ -f $state/original-bridge-nf ]] || cat /proc/sys/net/bridge/bridge-nf-call-iptables > "$state/original-bridge-nf"
sysctl -w net.bridge.bridge-nf-call-iptables=0
"${compose[@]}" config --quiet
"${xoc[@]}" lab check --plan "$plan_name"

stage image-build
"$runtime/bin/python" "$release/scripts/setup-siem-manager.py" "$release" "$plan_name"
if "$runtime/bin/python" -c 'import json,sys; sys.exit("siem-ui" not in json.load(open(sys.argv[1]))["lock"]["selected"])' "$plan_json"; then
    stage siem-ui-identities
    "$runtime/bin/python" "$release/scripts/setup-siem-ui.py" prepare "$release" "$plan_name" "$public_host"
    printf 'vm.max_map_count = 262144\n' > /etc/sysctl.d/70-xocrange-indexer.conf
    if [[ $(sysctl -n vm.max_map_count) -lt 262144 ]]; then sysctl -w vm.max_map_count=262144; fi
fi
stage platform-identities
systemctl stop xocrange-observer.timer xocrange-observer.service 2>/dev/null || true
"$runtime/bin/python" "$release/scripts/setup-platform.py" "$release" "$plan_name" "$public_host"
"${compose[@]}" build
stage start-services
systemctl disable --now xocrange-collector.service 2>/dev/null || true
if systemctl is-active --quiet xocrange-core.service; then
    systemctl stop xocrange-core.service
fi
"${xoc[@]}" lab start --plan "$plan_name" --isolated-vm
stage acceptance
"${xoc[@]}" lab verify --plan "$plan_name" --isolated-vm | tee "$state/acceptance-$run_id.json"

stage boot-service
# Reboot starts the same validated plan and local images; never silently rebuilds.
cat > /etc/systemd/system/xocrange-core.service <<EOF
[Unit]
Description=xOC Range Core experimental security path
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target
RequiresMountsFor=$data_directory $release

[Service]
Type=oneshot
RemainAfterExit=yes
Environment=PYTHONDONTWRITEBYTECODE=1
WorkingDirectory=$release
ExecStartPre=/usr/sbin/modprobe -a br_netfilter nfnetlink_queue nfnetlink_log
ExecStartPre=/usr/sbin/sysctl -w net.bridge.bridge-nf-call-iptables=0
ExecStart=$runtime/bin/xoc --root $release lab start --plan $plan_name --isolated-vm
ExecStartPost=$runtime/bin/xoc --root $release lab verify --plan $plan_name --isolated-vm
ExecStartPost=$runtime/bin/python $release/scripts/setup-siem-manager.py $release $plan_name check
ExecStartPost=$runtime/bin/python $release/scripts/setup-siem-ui.py initialize $release $plan_name
ExecStop=$runtime/bin/xoc --root $release lab down --plan $plan_name --isolated-vm
TimeoutStartSec=600
TimeoutStopSec=120
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now xocrange-core.service
stage registry-observer
bash "$release/scripts/install-registry.sh" "$release" "$runtime" "$plan_name"
stage management-acceptance
"$runtime/bin/python" "$release/scripts/verify-management.py" "$release"
if "$runtime/bin/python" -c 'import json,sys; sys.exit("siem" not in json.load(open(sys.argv[1]))["lock"]["selected"])' "$plan_json"; then
    stage siem-telemetry
    bash "$release/scripts/install-telemetry.sh" "$release" "$runtime" "$plan_name"
    "$runtime/bin/python" "$release/scripts/verify-siem.py" "$release" "$plan_name"
    if "$runtime/bin/python" -c 'import json,sys; sys.exit("siem-ui" not in json.load(open(sys.argv[1]))["lock"]["selected"])' "$plan_json"; then
        stage siem-ui-acceptance
        "$runtime/bin/python" "$release/scripts/verify-siem-ui.py" "$release" "$plan_name"
    fi
else
    systemctl disable --now xocrange-collector.service xocrange-osquery.service 2>/dev/null || true
    if [[ -f $state/telemetry-owned ]]; then
        systemctl disable --now sysmon.service
        python3 "$release/scripts/configure-audit.py" "$release/components/siem/audit.rules" --remove
        python3 -c 'from pathlib import Path; Path("/etc/audit/rules.d/70-xocrange.rules").unlink(missing_ok=True)'
    fi
fi
ln -sfn "$release" "$prefix/current"
cat > /usr/local/bin/xoc <<EOF
#!/bin/sh
exec "$runtime/bin/xoc" --root "$release" "\$@"
EOF
chmod 0755 /usr/local/bin/xoc
"$runtime/bin/python" - "$state/last-install.json" "$release" "$plan_name" "$data_directory" "$log" "$state/acceptance-$run_id.json" "$plan_json" <<'PY'
import json,sys
from pathlib import Path
report = json.loads(Path(sys.argv[6]).read_text())
assert report['status'] == 'passed' and report['checks'] and all(report['checks'].values())
selected = json.loads(Path(sys.argv[7]).read_text())['lock']['selected']
result = dict(status='installed', scope='experimental-security-path', release=sys.argv[2], selected=selected,
              plan=sys.argv[3], data_directory=sys.argv[4], log=sys.argv[5], acceptance=report,
              community_complete=False, reboot_verified=False)
management=json.loads(Path('/var/lib/xocrange/management-acceptance.json').read_text())
assert management['status']=='passed' and all(management['checks'].values())
result['management_acceptance']=management
if 'siem' in selected:
    siem = json.loads(Path('/var/lib/xocrange/siem-acceptance.json').read_text())
    assert siem['status'] == 'passed' and all(siem['checks'].values())
    result.update(scope='experimental-security-path-and-siem', siem_acceptance=siem)
if 'siem-ui' in selected:
    ui=json.loads(Path('/var/lib/xocrange/siem-ui-acceptance.json').read_text())
    assert ui['status']=='passed' and all(ui['checks'].values())
    result.update(scope='experimental-security-path-and-siem-ui',siem_ui_acceptance=ui)
Path(sys.argv[1]).write_text(json.dumps(result, indent=2) + '\n')
PY
printf '\nInstalled and verified: experimental platform + fw + IPS + WAF.\n'
printf 'State: %s/last-install.json\nLogs: %s\n' "$state" "$log"
printf 'Optional workspaces follow the selected plan. The complete Community release remains under development.\n'
printf 'Core login details: sudo xoc platform credentials\n'
if ((${#ui_selection[@]})); then
    printf 'SIEM login details: sudo xoc siem credentials\nLocal CA certificate: /etc/xocrange/ca.crt\n'
fi
