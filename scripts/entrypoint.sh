#!/bin/sh
set -eu
umask 077
mkdir -p /run/fortiproxy
chmod 700 /run/fortiproxy
if [ ! -c /dev/ppp ]; then mknod /dev/ppp c 108 0; fi
cp /etc/resolv.conf /run/fortiproxy/bootstrap-resolv.conf
/usr/local/bin/fortiproxy-firewall
# Proxy UID cannot reach Docker DNS on loopback. openfortivpn installs VPN DNS;
# root retains a bootstrap resolver for gateway hostname resolution on reconnect.
setpriv --reuid=10001 --regid=10001 --clear-groups --bounding-set=-all --no-new-privs microsocks -i 0.0.0.0 -p 1080 &
socks_pid=$!
setpriv --reuid=10001 --regid=10001 --clear-groups --bounding-set=-all --no-new-privs tinyproxy -d -c /etc/fortiproxy/tinyproxy.conf &
http_pid=$!
python3 -m app.server &
ui_pid=$!
trap 'kill "$ui_pid" "$socks_pid" "$http_pid" 2>/dev/null || true; wait' TERM INT EXIT
while kill -0 "$ui_pid" 2>/dev/null && kill -0 "$socks_pid" 2>/dev/null && kill -0 "$http_pid" 2>/dev/null; do sleep 1; done
exit 1
