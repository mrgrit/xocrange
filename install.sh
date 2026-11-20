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
  --restore PATH     Install prerequisites, then restore a verified private backup
  --livefire HOST    Live Fire Range Control address (default: look for one on the local network)
  --no-livefire      Install Core only; do not look for a Live Fire server
  --enroll-code CODE Class enrollment code from the instructor (otherwise asked when a server is found)
  --lab-domain NAME  This learner's lab domain, e.g. alice.lab (otherwise asked)
  --trust-vendor-key FILE  Vendor public key the Live Fire license must chain to (if not trusted yet)
  --dry-run          Describe operations without installing or accessing the network
  --help            Show this help

Live Fire (ADR 0011): when a licensed Range Control answers on the local network and a class
code is given, the Core is enrolled with the learner's lab domain (targets as dvwa.<domain>).
Without a server or a code, Core is installed alone (xoc.range names, hosts file only).

Running this development installer selects the experimental security-path profile.
An existing unrelated Docker/containerd installation is never removed or migrated.
EOF
}

# Ubuntu's automatic package maintenance may hold the lists lock even when
# DPkg::Lock::Timeout is set. Retry only lock contention, with a bounded wait.
apt_retry() {
    local output attempt rc=100
    output=$(mktemp)
    for ((attempt=1; attempt<=30; attempt++)); do
        if LC_ALL=C apt-get "$@" >"$output" 2>&1; then
            cat "$output"; rm -f "$output"; return 0
        else rc=$?; fi
        cat "$output"
        if ! grep -Eq 'Could not get lock|Unable to acquire the dpkg|Unable to lock directory|is another process using it' "$output"; then
            rm -f "$output"; return "$rc"
        fi
        if ((attempt<30)); then printf 'APT maintenance is running; waiting for its lock.\n'; sleep 10; fi
    done
    rm -f "$output"; return "$rc"
}
export -f apt_retry

fail() { printf 'xOC install failed: %s\n' "$*" >&2; exit 2; }
stage() {
    current_stage=$1; printf '\n[xOC] %s\n' "$current_stage"
    if [[ -n ${checkpoint:-} && -f $checkpoint/manifest.json ]]; then
        printf '{"status":"in-progress","stage":"%s","checkpoint":"%s","candidate":"%s"}\n' \
            "$current_stage" "$checkpoint" "$release" > "$state/install-operation.tmp"
        mv "$state/install-operation.tmp" "$state/install-operation.json"
    fi
}
need_value() { [[ $# -ge 2 && -n $2 && $2 != --* ]] || fail "Missing value for $1"; }
selection=()
siem_selection=(--include siem)
ui_selection=(--include siem-ui)
management_selection=(--include management)
optional_selection=()
public_host=
data_directory=/var/lib/xocrange/data
source_ref=
downloaded=
restore_path=
expected_install=
dry_run=false
livefire_mode=auto
livefire_server=
enroll_code=
lab_domain=
trust_vendor_key=
livefire_staging=
while (($#)); do
    case "$1" in
        --include|--without)
            need_value "$@"
            [[ $2 =~ ^[a-z][a-z0-9-]{0,63}$ ]] || fail 'Invalid module ID'
            selection+=("$1" "$2"); shift 2 ;;
        --data-dir) need_value "$@"; data_directory=$2; shift 2 ;;
        --public-host) need_value "$@"; public_host=$2; shift 2 ;;
        --restore) need_value "$@"; restore_path=$2; shift 2 ;;
        --expected-install)
            need_value "$@"
            [[ $2 =~ ^[a-f0-9]{64}:[a-f0-9]{64}$ ]] || fail 'Invalid expected installation identity'
            expected_install=$2; shift 2 ;;
        --ref)
            need_value "$@"
            [[ $2 =~ ^[0-9a-f]{40}$ ]] || fail '--ref requires a full Git commit hash'
            source_ref=$2; shift 2 ;;
        --livefire) need_value "$@"; livefire_server=$2; shift 2 ;;
        --no-livefire) livefire_mode=off; shift ;;
        --enroll-code)
            need_value "$@"
            [[ $2 =~ ^[A-Za-z0-9-]{8,16}$ ]] || fail 'Invalid enrollment code'
            enroll_code=$2; shift 2 ;;
        --lab-domain)
            need_value "$@"
            [[ $2 =~ ^[A-Za-z0-9.-]{3,253}$ ]] || fail 'Invalid lab domain'
            lab_domain=$2; shift 2 ;;
        --trust-vendor-key) need_value "$@"; trust_vendor_key=$(realpath -e -- "$2") || fail 'Vendor key file not found'; shift 2 ;;
        --dry-run) dry_run=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *) fail "Unknown option: $1" ;;
    esac
done
for ((i=0; i<${#selection[@]}; i++)); do
    if [[ ${selection[i]} == --without && ${selection[i+1]:-} == siem ]]; then siem_selection=(); ui_selection=(); fi
    if [[ ${selection[i]} == --without && ${selection[i+1]:-} == siem-ui ]]; then ui_selection=(); fi
done
for console_id in console-fw console-ips console-waf portal noc academy-reader office-pc attacker; do
    console_excluded=false
    for ((i=0; i<${#selection[@]}; i++)); do
        if [[ ${selection[i]} == --without && ${selection[i+1]:-} == "$console_id" ]]; then console_excluded=true; fi
    done
    if ! $console_excluded; then optional_selection+=(--include "$console_id"); fi
done
[[ $data_directory =~ ^/[A-Za-z0-9_/-]+$ && $data_directory != / ]] || fail 'Invalid data directory'
[[ -z $public_host || $public_host =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$ ]] || fail 'Invalid public hostname'
[[ -z $livefire_server || $livefire_server =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$ ]] || fail 'Invalid Live Fire server address'
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
# Log maintenance holds this lock briefly every minute; wait out that overlap.
flock -w 120 9 || fail 'Another xOC installation is in progress'
if [[ -n $expected_install ]]; then
    actual_install=$(python3 -c 'import json,pathlib; s=json.load(open("/var/lib/xocrange/last-install.json")); print(pathlib.Path(s["release"]).name+":"+s["plan"].removeprefix("install-"))')
    [[ $actual_install == "$expected_install" ]] || fail 'The installed selection changed; preview the operation again'
fi

state=/var/lib/xocrange
prefix=/opt/xocrange
install -d -m 0700 "$state" /var/log/xocrange
install -d -m 0755 "$prefix"
run_id=$(date -u +%Y%m%dT%H%M%S)-$$
log=/var/log/xocrange/install-$run_id.log
exec > >(tee -a "$log") 2>&1
current_stage=preflight
checkpoint=
on_exit() {
    code=$?
    if [[ -n ${downloaded:-} && -d $downloaded ]]; then rm -rf -- "$downloaded"; fi
    if [[ -n ${livefire_staging:-} && -d $livefire_staging ]]; then rm -rf -- "$livefire_staging"; fi
    if ((code)); then
        printf '{"status":"failed","stage":"%s","exit_code":%s,"log":"%s"}\n' \
            "$current_stage" "$code" "$log" > "$state/last-attempt.json"
        printf '\nInstallation did not complete. Stage: %s. Log: %s\n' "$current_stage" "$log" >&2
        if [[ -n $checkpoint && -f $checkpoint/manifest.json ]]; then
            trap - EXIT
            printf 'Restoring the last verified installation: %s\n' "$checkpoint"
            if "$runtime/bin/python" "$release/scripts/appliance-ops.py" rollback "$checkpoint"; then
                printf '{"status":"rolled-back","checkpoint":"%s"}\n' "$checkpoint" > "$state/install-operation.json"
            else
                printf '{"status":"recovery-required","checkpoint":"%s"}\n' "$checkpoint" > "$state/install-operation.json"
                printf 'Automatic rollback needs recovery. Backup: %s\n' "$checkpoint" >&2
            fi
        fi
    fi
    resume_apt_maintenance
}
# Unattended upgrades can re-execute systemd during installation (a libc6
# upgrade does). That drops in-flight `systemctl` jobs with "D-Bus connection
# terminated" and fails a healthy install. Pause the periodic APT timers for
# this run and let a run that already started finish first.
paused_apt_timers=()
pause_apt_maintenance() {
    local timer unit waited=0
    for timer in apt-daily.timer apt-daily-upgrade.timer; do
        if systemctl is-active --quiet "$timer"; then
            systemctl stop "$timer" && paused_apt_timers+=("$timer")
        fi
    done
    for unit in apt-daily-upgrade.service apt-daily.service; do
        while [[ $(systemctl show -p ActiveState --value "$unit" 2>/dev/null) == activating ]] && ((waited < 1800)); do
            ((waited % 60)) || printf 'Waiting for automatic package maintenance (%s) to finish.\n' "$unit"
            sleep 5; waited=$((waited + 5))
        done
    done
}
resume_apt_maintenance() {
    if ((${#paused_apt_timers[@]})); then systemctl start "${paused_apt_timers[@]}" || true; fi
}
trap on_exit EXIT
pause_apt_maintenance

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
# Earlier installers left xOC keys root-only (umask 077); apt's unprivileged gpgv
# then rejects the repository and every later apt update fails.
for key in /etc/apt/keyrings/xocrange-*.asc; do
    if [[ -f $key ]]; then chmod 0644 "$key"; fi
done
apt_retry "${apt_options[@]}" update
base_missing=()
for package in ca-certificates curl git python3 python3-venv iproute2 kmod openssl; do
    if [[ $(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true) != 'install ok installed' ]]; then
        base_missing+=("$package")
    fi
done
if ((${#base_missing[@]})); then apt_retry "${apt_options[@]}" install -y --no-install-recommends "${base_missing[@]}"; fi

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
content_selected=false
for ((i=0; i<${#optional_selection[@]}; i+=2)); do
    if [[ ${optional_selection[i+1]} == academy-reader ]]; then content_selected=true; fi
done
for ((i=0; i<${#selection[@]}; i+=2)); do
    if [[ ${selection[i+1]} == academy-reader ]]; then
        if [[ ${selection[i]} == --include ]]; then content_selected=true; else content_selected=false; fi
    fi
done
if $content_selected; then
    stage content-module
    python3 "$source_directory/scripts/verify-contents.py" --root "$source_directory"
fi
stage source-snapshot
release=$(python3 "$source_directory/scripts/install-support.py" snapshot "$source_directory" "$prefix/releases")
# The immutable release now holds the source; a downloaded checkout is no longer needed.
if [[ -n $downloaded ]]; then rm -rf -- "$downloaded"; downloaded=; fi
runtime=$prefix/venvs/$(basename "$release")
[[ -x $runtime/bin/python ]] || python3 -m venv "$runtime"
"$runtime/bin/python" -m pip install --require-hashes -r "$release/requirements.lock"
"$runtime/bin/python" -m pip install --no-deps "$release"
xoc=("$runtime/bin/xoc" --root "$release")

# Live Fire enrollment (ADR 0011) before the plan, so the platform starts with the learner's
# domain. Already enrolled Cores, updates without a terminal and --no-livefire skip it.
# Enrollment results are kept in $livefire_dir as soon as they arrive: if a later step fails,
# the next run activates them instead of enrolling again (no second code use or seat).
livefire_dir=/etc/xocrange/livefire
livefire_enrolled=
if [[ -f $livefire_dir/enrollment.json ]]; then
    livefire_mode=off
    livefire_enrolled=$("$runtime/bin/python" -c 'import json,sys; print(json.load(open(sys.argv[1]))["domain"])' "$livefire_dir/enrollment.json")
elif [[ -f $livefire_dir/pending/enrollment.json ]]; then
    livefire_mode=stored
elif [[ $livefire_mode == auto && -z $enroll_code && ! -t 0 ]]; then
    livefire_mode=off
fi
if [[ $livefire_mode == auto ]]; then
    stage livefire-enrollment
    livefire_staging=$state/livefire-$run_id
    install -d -m 0700 "$livefire_staging"
    enroll_args=(run --out "$livefire_staging" --trust-dir /etc/xocrange/entitlements/trust --targets)
    for ((i=0; i<${#selection[@]}; i+=2)); do
        if [[ ${selection[i]} == --include && ${selection[i+1]} == target-* ]]; then enroll_args+=("${selection[i+1]#target-}"); fi
    done
    if [[ -n $livefire_server ]]; then enroll_args+=(--server "$livefire_server"); fi
    if [[ -n $enroll_code ]]; then enroll_args+=(--code "$enroll_code"); fi
    if [[ -n $lab_domain ]]; then enroll_args+=(--domain "$lab_domain"); fi
    if [[ -n $trust_vendor_key ]]; then enroll_args+=(--trust-key "$trust_vendor_key"); fi
    if [[ -t 0 ]]; then enroll_args+=(--interactive); fi
    enroll_status=0
    "$runtime/bin/python" -I "$release/scripts/livefire-enroll.py" "${enroll_args[@]}" > "$livefire_staging/result.json" || enroll_status=$?
    case $enroll_status in
        0)
            install -d -m 0700 "$livefire_dir" "$livefire_dir/pending" "$livefire_dir/pending/credentials"
            install -m 0600 "$livefire_staging"/credentials/* "$livefire_dir/pending/credentials/"
            install -m 0600 "$livefire_staging/license.json" "$livefire_staging/identity.json" "$livefire_dir/pending/"
            install -m 0644 "$livefire_staging/vendor.pem" "$livefire_staging/enrollment.json" "$livefire_dir/pending/"
            livefire_mode=stored
            ;;
        3) ;;   # no server or no code: Core only (the message was printed)
        *) fail 'Live Fire enrollment did not complete (see the message above). To install Core only, add --no-livefire.' ;;
    esac
    rm -rf -- "$livefire_staging"; livefire_staging=
fi
if [[ $livefire_mode == stored ]]; then
    stage livefire-activation
    # The installer already holds the operation lock: call the license functions directly.
    install -d -m 0755 /etc/xocrange/entitlements
    "$runtime/bin/python" - "$release" "$livefire_dir/pending" <<'PY'
import json
import sys
from pathlib import Path
from xocrange.entitlements import manage
root, pending = Path(sys.argv[1]), Path(sys.argv[2])
summary = json.loads((pending / 'enrollment.json').read_text())
manage(root, 'trust', file=pending / 'vendor.pem', key_id=summary['vendor_key_id'])
manage(root, 'activate', file=pending / 'license.json', institution=summary['institution_id'], range_id=summary['range_id'])
PY
    rm -rf -- "$livefire_dir/credentials"
    mv "$livefire_dir/pending/credentials" "$livefire_dir/credentials"
    mv "$livefire_dir/pending/enrollment.json" "$livefire_dir/enrollment.json"
    rm -rf -- "$livefire_dir/pending"
    livefire_enrolled=$("$runtime/bin/python" -c 'import json,sys; print(json.load(open(sys.argv[1]))["domain"])' "$livefire_dir/enrollment.json")
    printf '[Live Fire] License activated for %s.\n' "$livefire_enrolled"
fi

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
    apt_retry "${apt_options[@]}" update
fi
missing_packages=()
for package in docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; do
    if [[ $(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true) != 'install ok installed' ]]; then
        missing_packages+=("$package")
    fi
done
if ((${#missing_packages[@]})); then
    apt_retry "${apt_options[@]}" install -y --no-install-recommends "${missing_packages[@]}"
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
if [[ -f $state/last-install.json ]]; then
    # An update builds its images while the running installation is still untouched: a build that
    # fails here ends the update with nothing stopped and nothing to restore. The running services
    # keep their own retained images (images.lock.json), so new tags do not affect them. The build
    # after the checkpoint then comes from the cache.
    if [[ ! -f $release/.local/plans/$plan_name/images.lock.json ]]; then
        "${compose[@]}" pull --ignore-buildable
        "${compose[@]}" build
    fi
    checkpoint=$state/backups/before-install-$run_id
    "$runtime/bin/python" "$release/scripts/appliance-ops.py" checkpoint "$checkpoint"
    stage update-transaction
fi
"$runtime/bin/python" "$release/scripts/setup-siem-manager.py" "$release" "$plan_name"
if "$runtime/bin/python" -c 'import json,sys; sys.exit("siem" not in json.load(open(sys.argv[1]))["lock"]["selected"])' "$plan_json"; then
    stage evidence-store
    # Schema/index migrations on a large evidence DB finish before collector
    # and acceptance readers race for the same SQLite schema write lock.
    "$runtime/bin/python" -c 'from xocrange.event_store import Store; store=Store("/var/lib/xocrange/siem"); store.db.close()'
fi
if "$runtime/bin/python" -c 'import json,sys; sys.exit("siem-ui" not in json.load(open(sys.argv[1]))["lock"]["selected"])' "$plan_json"; then
    stage siem-ui-identities
    "$runtime/bin/python" "$release/scripts/setup-siem-ui.py" prepare "$release" "$plan_name" "$public_host"
    printf 'vm.max_map_count = 262144\n' > /etc/sysctl.d/70-xocrange-indexer.conf
    if [[ $(sysctl -n vm.max_map_count) -lt 262144 ]]; then sysctl -w vm.max_map_count=262144; fi
fi
stage platform-identities
systemctl stop xocrange-observer.timer xocrange-observer.service 2>/dev/null || true
"$runtime/bin/python" "$release/scripts/setup-platform.py" "$release" "$plan_name" "$public_host"
if [[ ! -f $release/.local/plans/$plan_name/images.lock.json ]]; then
    "${compose[@]}" pull --ignore-buildable
    "${compose[@]}" build
    "$runtime/bin/python" "$release/scripts/lock-images.py" "$release/.local/plans/$plan_name"
fi
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
ExecStart=$runtime/bin/xoc --root $release lab resume --plan $plan_name --isolated-vm
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
    if "$runtime/bin/python" -c 'import json,sys; sys.exit("office-pc" not in json.load(open(sys.argv[1]))["lock"]["selected"])' "$plan_json"; then
        stage office-agent
        "$runtime/bin/python" "$release/scripts/setup-office.py" "$release" "$plan_name"
    fi
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
cp "$state/last-install.json" "$state/last-attempt.json"
stage operational-maintenance
bash "$release/scripts/install-operations.sh" "$release" "$runtime"
if [[ -n $livefire_enrolled ]]; then
    # Class domain list -> managed /etc/hosts block (ADR 0011). Only on enrolled Cores.
    stage livefire-hosts
    printf '%s\n' '[Unit]' 'Description=xOC Range Live Fire: class domain list into /etc/hosts' \
        'After=network-online.target' '' '[Service]' 'Type=oneshot' \
        "ExecStart=/usr/bin/python3 -I $prefix/current/scripts/livefire-hosts.py" \
        'NoNewPrivileges=yes' 'ProtectHome=yes' 'PrivateTmp=yes' \
        > /etc/systemd/system/xocrange-livefire-hosts.service
    printf '%s\n' '[Unit]' 'Description=xOC Range Live Fire: refresh the class domain list' '' '[Timer]' \
        'OnBootSec=1min' 'OnUnitActiveSec=2min' 'RandomizedDelaySec=20s' '' '[Install]' 'WantedBy=timers.target' \
        > /etc/systemd/system/xocrange-livefire-hosts.timer
    systemctl daemon-reload
    systemctl enable --now xocrange-livefire-hosts.timer >/dev/null
    systemctl start xocrange-livefire-hosts.service || printf 'Warning: the class domain list was not fetched yet; the timer retries.\n' >&2
fi
stage release-inventory
"$runtime/bin/python" "$release/scripts/release-inventory.py" "$release" "$plan_name"
printf '{"status":"complete","release":"%s","checkpoint":"%s"}\n' "$release" "$checkpoint" > "$state/install-operation.json"
if [[ -n $checkpoint ]]; then
    # Older pre-install checkpoints are superseded by this one; keep disk bounded.
    "$runtime/bin/python" "$release/scripts/appliance-ops.py" prune-checkpoints "$checkpoint" || printf 'Warning: older checkpoints were not pruned\n' >&2
fi
checkpoint=
if [[ -n $restore_path ]]; then
    stage backup-restore
    "$runtime/bin/python" "$release/scripts/appliance-ops.py" restore "$restore_path"
fi
printf '\nInstalled and verified: experimental platform + fw + IPS + WAF.\n'
printf 'State: %s/last-install.json\nLogs: %s\n' "$state" "$log"
printf 'Optional workspaces follow the selected plan. The complete Community release remains under development.\n'
printf 'Core login details: sudo xoc platform credentials\n'
if [[ -n $livefire_enrolled ]]; then
    printf 'Live Fire: enrolled as %s (targets as dvwa.%s). Classmates are reached by their own domains.\n' "$livefire_enrolled" "$livefire_enrolled"
    printf 'Assessor module credentials: sudo xoc module credentials m15-assessor --from %s/credentials\n' "$livefire_dir"
fi
if ((${#ui_selection[@]})); then
    printf 'SIEM login details: sudo xoc siem credentials\nLocal CA certificate: /etc/xocrange/ca.crt\n'
fi
