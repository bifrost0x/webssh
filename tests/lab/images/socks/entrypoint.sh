#!/bin/sh
set -eu
mode="${LAB_SOCKS_MODE:-open}"
if [ "$mode" = auth ]; then
    LAB_SOCKS_LABPROXY="$(head -n1 /lab/secrets/socks-labproxy)"
    id -u labproxy >/dev/null 2>&1 || adduser -D -H -s /sbin/nologin labproxy
    printf 'labproxy:%s\n' "$LAB_SOCKS_LABPROXY" | chpasswd
fi
exec sockd -f "/etc/sockd-$mode.conf"
