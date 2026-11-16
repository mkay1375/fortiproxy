#!/bin/sh
set -eu
# Only replies to incoming clients may leave on the Docker interface. New proxy
# connections (including DNS) must go through the VPN; losing ppp0 fails closed.
for tool in iptables ip6tables; do
    "$tool" -N FORTIPROXY
    "$tool" -A FORTIPROXY -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j ACCEPT
    # Policy rerouting may finish after OUTPUT filtering; enforce the actual
    # final interface in POSTROUTING before any packet can leave.
    "$tool" -A FORTIPROXY -m mark --mark 108 -j ACCEPT
    "$tool" -A FORTIPROXY -j REJECT
    "$tool" -I OUTPUT 1 -m owner --uid-owner 10001 -j FORTIPROXY
    "$tool" -t mangle -A POSTROUTING -m owner --uid-owner 10001 -m conntrack --ctdir ORIGINAL ! -o ppp0 -j DROP
    # VPN peers may reply to our connections, but cannot initiate connections
    # to the control panel/proxies or use this container as an IP router.
    "$tool" -I INPUT 1 -i ppp0 -j DROP
    "$tool" -I INPUT 1 -i ppp0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    "$tool" -P FORWARD DROP
done

# Mark only connections initiated by proxy processes. Replies to incoming proxy
# clients keep normal Docker routes, even when their source is outside its subnet.
iptables -t mangle -A OUTPUT -m owner --uid-owner 10001 -m conntrack --ctdir ORIGINAL -j MARK --set-mark 108
ip rule add fwmark 108 lookup 108 priority 108
ip route add unreachable default table 108 metric 32767
ip6tables -t mangle -A OUTPUT -m owner --uid-owner 10001 -m conntrack --ctdir ORIGINAL -j MARK --set-mark 108
ip -6 rule add fwmark 108 lookup 108 priority 108
ip -6 route add unreachable default table 108 metric 32767

# OUTPUT policy rerouting may retain the source address selected on eth0.
# Translate it to the tunnel address before sending it to the VPN gateway.
iptables -t nat -A POSTROUTING -o ppp0 -m mark --mark 108 -j MASQUERADE
