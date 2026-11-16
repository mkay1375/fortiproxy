FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 openfortivpn ppp microsocks tinyproxy iproute2 iptables ca-certificates util-linux tini && rm -rf /var/lib/apt/lists/* && groupadd -g 10001 proxyvpn && useradd -u 10001 -g 10001 -M -s /usr/sbin/nologin proxyvpn
WORKDIR /opt/fortiproxy
LABEL org.opencontainers.image.licenses="MIT"
COPY LICENSE ./LICENSE
COPY app ./app
COPY web ./web
COPY scripts/firewall.sh /usr/local/bin/fortiproxy-firewall
COPY scripts/entrypoint.sh /usr/local/bin/fortiproxy-entrypoint
COPY scripts/tinyproxy.conf /etc/fortiproxy/tinyproxy.conf
RUN chmod 755 /usr/local/bin/fortiproxy-* && mkdir -p /run/fortiproxy && chmod 700 /run/fortiproxy
EXPOSE 8787 1080 8080
HEALTHCHECK --interval=15s --timeout=3s CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/api/status',timeout=2)"
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/fortiproxy-entrypoint"]
