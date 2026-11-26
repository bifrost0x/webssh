#!/bin/sh
# Builds an isolated routing setup inside a throwaway container namespace.
# Runs as root in that namespace only; the lab is not touched.
set -eu
ip link add tailscale0 type dummy
ip link add lan0 type dummy
ip link set tailscale0 up
ip link set lan0 up
ip addr add 100.100.1.2/32 dev tailscale0
ip addr add 192.0.2.2/24 dev lan0
ip -6 addr add 2001:db8::2/64 dev lan0 nodad
ip route add 100.100.0.0/16 dev tailscale0 table 52
ip route add blackhole 100.90.0.0/16 table 52
ip route add prohibit 100.91.0.0/16 table 52
ip -6 route add fd7a:115c:a1e0::/48 dev tailscale0 table 52
ip route add 100.80.0.0/16 dev lan0
ip rule add pref 5270 table 52
ip -6 rule add pref 5270 table 52
exec "$@"
