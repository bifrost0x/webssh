#!/bin/sh
# Fresh directory from the per-run LDIF on every start.
set -eu
name="${LAB_LDAP_NAME:?}"
conf=/etc/openldap/slapd-lab.conf
rootpw="$(cat /lab/ldap/rootpw-"$name")"
sed -e "s|@NAME@|$name|g" -e "s|@ROOTPW@|$rootpw|" /etc/openldap/lab-slapd.conf.in > "$conf"
chmod 0640 "$conf"
chgrp ldap "$conf"

# slapd runs as ldap and cannot traverse the runtime mount; copy its TLS files.
install -d -m 0750 -o root -g ldap /etc/openldap/tls
install -m 0644 /lab/ca/ca.crt /etc/openldap/tls/ca.crt
install -m 0644 "/lab/tls/$name.crt" /etc/openldap/tls/server.crt
install -m 0640 -o root -g ldap "/lab/tls/$name.key" /etc/openldap/tls/server.key

rm -rf "/var/lib/openldap/$name"
install -d -m 0700 -o ldap -g ldap "/var/lib/openldap/$name" /run/openldap
slapadd -f "$conf" -l "/lab/ldap/$name.ldif"
chown -R ldap:ldap "/var/lib/openldap/$name"
slaptest -u -f "$conf"

urls="ldap:///"
[ "$name" = ldap1 ] && urls="ldap:/// ldaps:///"
exec slapd -d stats -u ldap -g ldap -f "$conf" -h "$urls"
