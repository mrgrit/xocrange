FROM wazuh/wazuh-manager:4.14.10@sha256:dcda4869e2f792e92f03bce93f85b4bdf103756ea61cfca8ba9f3eabeb05365b
RUN cp -a /var/ossec/data_tmp/permanent/var/ossec/. /var/ossec/ && \
    cp -a /var/ossec/data_tmp/exclusion/var/ossec/. /var/ossec/ && \
    ln -sf ../../var/ar.conf /var/ossec/etc/shared/ar.conf && \
    rmdir /var/ossec/stats && ln -s var/stats /var/ossec/stats
COPY ossec.conf c1-decoder.xml c1-rules.xml native-decoders.xml native-rules.xml /opt/xoc-config/
COPY start.sh /usr/local/bin/xoc-siem-start
COPY queue.py /usr/local/lib/xoc-queue.py
COPY native-queue.py /usr/local/lib/xoc-native-queue.py
COPY bootstrap.py /usr/local/lib/xoc-manager-bootstrap.py
RUN mkdir -p /opt/xoc-manager-seed/api && \
    cp -a /var/ossec/etc /var/ossec/queue /var/ossec/var /opt/xoc-manager-seed/ && \
    cp -a /var/ossec/api/configuration /opt/xoc-manager-seed/api/ && \
    rm -rf /var/ossec/etc/* /var/ossec/queue/* /var/ossec/var/* /var/ossec/api/configuration/* && \
    chmod 0755 /usr/local/bin/xoc-siem-start && \
    chmod 0644 /usr/local/lib/xoc-manager-bootstrap.py
ENTRYPOINT ["/usr/local/bin/xoc-siem-start"]
