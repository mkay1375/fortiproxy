#!/bin/sh
set -eu
# Only replies to incoming clients may leave on the Docker interface. New proxy
# connections (including DNS) must go through the VPN; losing ppp0 fails closed.
for tool in iptables ip6tables; do
    "$tool" -N FORTIPROXY
    "$tool" -A FORTIPROXY -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j ACCEPT
    "$tool" -A FORTIPROXY -o ppp0 -j ACCEPT
    "$tool" -A FORTIPROXY -j REJECT
    "$tool" -I OUTPUT 1 -m owner --uid-owner 10001 -j FORTIPROXY
done

# Mark only connections initiated by proxy processes. Replies to incoming proxy
# clients keep normal Docker routes, even when their source is outside its subnet.
iptables -t mangle -A OUTPUT -m owner --uid-owner 10001 -m conntrack --ctdir ORIGINAL -j MARK --set-mark 108
ip rule add fwmark 108 lookup 108 priority 108
ip route add unreachable default table 108 metric 32767
ip6tables -t mangle -A OUTPUT -m owner --uid-owner 10001 -m conntrack --ctdir ORIGINAL -j MARK --set-mark 108
ip -6 rule add fwmark 108 lookup 108 priority 108
ip -6 route add unreachable default table 108 metric 32767
