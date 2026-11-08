FROM ubuntu:26.04@sha256:6a06111c3b0a8600feadb270aec771dc239bf407b25625f93f44ab00e11f4d3c
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 util-linux python3 apache2 libapache2-mod-security2 modsecurity-crs ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && a2enmod proxy proxy_http headers unique_id security2 ssl remoteip \
    && a2dissite 000-default
COPY runtime/console/ /usr/local/lib/xoc/console/
COPY runtime/entrypoint.sh /usr/local/bin/xoc-entrypoint
COPY web/start.py /usr/local/lib/xoc/start-web.py
COPY web/apache.conf /etc/apache2/conf-enabled/xoc.conf
COPY web/modsecurity.conf /etc/modsecurity/xoc.conf
COPY web/console.conf /etc/xoc/console.conf
COPY web/management.conf /etc/xoc/management.conf
COPY web/siem.conf /etc/xoc/siem.conf
COPY web/envvars /etc/apache2/envvars
RUN chmod 0755 /usr/local/bin/xoc-entrypoint \
    && chown -R 33:33 /var/log/apache2 \
    && printf 'Listen 8080\n' > /etc/apache2/ports.conf
ENTRYPOINT ["/usr/local/bin/xoc-entrypoint", "web"]
