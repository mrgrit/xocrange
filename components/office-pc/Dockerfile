FROM ubuntu:26.04@sha256:6a06111c3b0a8600feadb270aec771dc239bf407b25625f93f44ab00e11f4d3c
# A staff Linux PC on the office network (ADR 0012): SSH sign-in, auth.log through rsyslog,
# sudo, cron and a Wazuh agent that reports to the Manager. The agent version follows the
# Manager (tests/integration/agent).
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
        openssh-server openssh-client rsyslog sudo cron iproute2 util-linux procps less vim-tiny && \
    curl --fail --proto '=https' https://packages.wazuh.com/key/GPG-KEY-WAZUH -o /tmp/wazuh.asc && \
    gpg --batch --dearmor -o /usr/share/keyrings/wazuh.gpg /tmp/wazuh.asc && \
    printf 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main\n' > /etc/apt/sources.list.d/wazuh.list && \
    printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d && chmod 755 /usr/sbin/policy-rc.d && \
    apt-get update && apt-get install -y --no-install-recommends wazuh-agent=4.14.10-1 && \
    rm -f /etc/apt/sources.list.d/wazuh.list /usr/sbin/policy-rc.d /tmp/wazuh.asc && rm -rf /var/lib/apt/lists/* && \
    rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub && \
    sed -i 's/^session\s\+required\s\+pam_loginuid.so/session optional pam_loginuid.so/' /etc/pam.d/sshd /etc/pam.d/cron && \
    sed -i 's/^module(load="imklog"/#module(load="imklog"/' /etc/rsyslog.conf && \
    printf 'LANG=C.UTF-8\n' > /etc/default/locale
COPY ossec.conf /var/ossec/etc/ossec.conf
COPY sshd.conf /etc/ssh/sshd_config.d/10-xoc-office.conf
COPY start.sh /usr/local/sbin/xoc-office-start
RUN chown root:wazuh /var/ossec/etc/ossec.conf && chmod 0640 /var/ossec/etc/ossec.conf && chmod 0755 /usr/local/sbin/xoc-office-start
ENTRYPOINT ["/usr/local/sbin/xoc-office-start"]
