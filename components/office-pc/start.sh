#!/bin/bash
# Start script of the office PC. Runs as root inside its own container namespaces.
set -euo pipefail
umask 022
config=/run/xoc-office
data=/var/lib/xoc-office

# The IPS is this network's router. Nothing else needs NET_ADMIN.
ip route replace default via 10.20.70.1

# Host keys live in the data volume: an update does not change the PC's SSH identity.
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
        printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$account" > /etc/sudoers.d/90-xoc-office
        chmod 0440 /etc/sudoers.d/90-xoc-office
    fi
fi

install -d -m 0755 /var/log
touch /var/log/auth.log /var/log/syslog
chown syslog:adm /var/log/auth.log /var/log/syslog
rm -f /run/rsyslogd.pid
rsyslogd
cron

# The agent starts when the installer has placed this PC's key (after the Manager is up).
(
    while [[ ! -f $config/client.keys ]]; do sleep 5; done
    install -o root -g wazuh -m 0640 "$config/client.keys" /var/ossec/etc/client.keys
    /var/ossec/bin/wazuh-control start || true
) >/var/log/xoc-office-agent.log 2>&1 &

# sshd and every session it starts run without NET_ADMIN and SETPCAP: sudo cannot change
# this PC's addresses, routes or packet filters.
exec setpriv --bounding-set -net_admin,-setpcap --inh-caps -net_admin,-setpcap /usr/sbin/sshd -D
