FROM wazuh/wazuh-manager:4.14.10
RUN cp -a /var/ossec/data_tmp/exclusion/var/ossec/. /var/ossec/ && \
    ln -sf ../../var/ar.conf /var/ossec/etc/shared/ar.conf && \
    rmdir /var/ossec/stats && ln -s var/stats /var/ossec/stats
# Run the Wazuh analysis engine only. API/enrollment/active response are separate work.
COPY ossec.conf /var/ossec/etc/ossec.conf
COPY c1-decoder.xml /var/ossec/etc/xoc-decoders/xoc-c1.xml
COPY c1-rules.xml /var/ossec/etc/xoc-rules/xoc-c1.xml
COPY start.sh /usr/local/bin/xoc-siem-start
COPY queue.py /usr/local/lib/xoc-queue.py
RUN cp -p /var/ossec/ruleset/rules/0010-rules_config.xml /var/ossec/etc/xoc-rules/000-base.xml && \
    cp -a /var/ossec/var/db /opt/xoc-db && \
    chmod 0755 /usr/local/bin/xoc-siem-start && \
    chown root:wazuh /var/ossec/etc/ossec.conf /var/ossec/etc/xoc-decoders/xoc-c1.xml /var/ossec/etc/xoc-rules/xoc-c1.xml && \
    chmod 0640 /var/ossec/etc/ossec.conf /var/ossec/etc/xoc-decoders/xoc-c1.xml /var/ossec/etc/xoc-rules/xoc-c1.xml
ENTRYPOINT ["/usr/local/bin/xoc-siem-start"]
