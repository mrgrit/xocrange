FROM ubuntu:26.04@sha256:6a06111c3b0a8600feadb270aec771dc239bf407b25625f93f44ab00e11f4d3c
# The attack terminal of the bundled lessons (ADR 0013): the tools the lessons name, an SSH
# server for the learner, nothing that collects or scores.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl wget \
        openssh-server openssh-client sudo iproute2 iputils-ping dnsutils util-linux procps less vim \
        python3 netcat-openbsd net-tools nmap hydra sqlmap nikto gobuster dirb && \
    rm -rf /var/lib/apt/lists/* && rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub && \
    sed -i 's/^session\s\+required\s\+pam_loginuid.so/session optional pam_loginuid.so/' /etc/pam.d/sshd && \
    printf 'LANG=C.UTF-8\n' > /etc/default/locale && \
    (userdel -r ubuntu 2>/dev/null || true)
COPY sshd.conf /etc/ssh/sshd_config.d/10-xoc-attacker.conf
COPY start.sh /usr/local/sbin/xoc-attacker-start
RUN chmod 0755 /usr/local/sbin/xoc-attacker-start
ENTRYPOINT ["/usr/local/sbin/xoc-attacker-start"]
