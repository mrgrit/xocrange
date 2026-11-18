#!/bin/bash
# Start script of the attack terminal. Runs as root inside its own container namespaces.
set -euo pipefail
umask 022
config=/run/xoc-attacker
data=/var/lib/xoc-attacker

# The firewall is the way into the lab. Nothing else needs NET_ADMIN.
ip route replace default via 10.20.30.1

install -d -m 0700 "$data"
[[ -f $data/ssh_host_ed25519_key ]] || ssh-keygen -q -t ed25519 -N '' -f "$data/ssh_host_ed25519_key"
[[ -f $data/ssh_host_rsa_key ]] || ssh-keygen -q -t rsa -b 3072 -N '' -f "$data/ssh_host_rsa_key"
install -d -m 0755 /run/sshd

# The lab account comes from the installer: a name and a password hash, never a password.
if [[ -f $config/username && -f $config/password.hash ]]; then
    account=$(<"$config/username")
    if [[ $account =~ ^[a-z][a-z0-9-]{1,30}$ ]]; then
        id "$account" >/dev/null 2>&1 || useradd --create-home --shell /bin/bash "$account"
        [[ -d /home/$account ]] || { install -d -m 0750 "/home/$account"; cp -a /etc/skel/. "/home/$account/"; }
        chown -R "$account:$account" "/home/$account"
        printf '%s:%s\n' "$account" "$(<"$config/password.hash")" | chpasswd -e
        printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$account" > /etc/sudoers.d/90-xoc-attacker
        chmod 0440 /etc/sudoers.d/90-xoc-attacker
    fi
fi

# Lab names resolve to the firewall's external address: requests cross fw, IPS and WAF.
if [[ -f $config/hosts ]]; then
    grep -v ' # xoc-lab$' /etc/hosts > /tmp/hosts.new || true
    sed 's/$/ # xoc-lab/' "$config/hosts" >> /tmp/hosts.new
    cat /tmp/hosts.new > /etc/hosts; rm -f /tmp/hosts.new
fi

exec setpriv --bounding-set -net_admin,-setpcap --inh-caps -net_admin,-setpcap /usr/sbin/sshd -D
