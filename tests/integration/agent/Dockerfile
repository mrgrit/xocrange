FROM ubuntu:26.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl gnupg python3 && \
    curl --fail --proto '=https' https://packages.wazuh.com/key/GPG-KEY-WAZUH -o /tmp/wazuh.asc && \
    gpg --batch --dearmor -o /usr/share/keyrings/wazuh.gpg /tmp/wazuh.asc && \
    printf 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main\n' > /etc/apt/sources.list.d/wazuh.list && \
    printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d && chmod 755 /usr/sbin/policy-rc.d && \
    apt-get update && apt-get install -y --no-install-recommends wazuh-agent=4.14.10-1 && \
    rm -rf /var/lib/apt/lists/* /tmp/wazuh.asc
COPY ossec.conf /var/ossec/etc/ossec.conf
COPY start.sh /start.sh
RUN chmod 755 /start.sh
ENTRYPOINT ["/start.sh"]
