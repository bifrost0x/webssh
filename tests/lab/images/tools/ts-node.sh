#!/bin/sh
# Network namespace of the "WebSSH node" in the Tailscale stand-in.
# Moves the tailnet route out of the main table into table 52 behind a
# policy rule, like tailscaled does, so route checks must use the kernel FIB
# (RTM_GETROUTE) and not /proc/net/route.
set -eu
dev=tailscale0
ip link show "$dev" >/dev/null
subnet="$(ip -4 route show dev "$dev" proto kernel | awk '{print $1; exit}')"
if [ -n "$subnet" ]; then
    ip route del "$subnet" dev "$dev" proto kernel
fi
ip route replace 100.64.0.0/10 dev "$dev" table 52
ip rule show | grep -q 'lookup 52' || ip rule add pref 5270 lookup 52
echo "tailnet stand-in ready:"
ip -4 addr show dev "$dev" | awk '/inet /{print "  address", $2}'
ip rule show | sed 's/^/  rule /'
exec sleep infinity
