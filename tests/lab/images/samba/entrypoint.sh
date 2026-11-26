#!/bin/sh
# Users and passwords come from the read-only per-run runtime at /lab.
set -eu
secret() { head -n1 "/lab/secrets/$1"; }
LAB_SAMBA_SMBUSER="$(secret samba-smbuser)"
LAB_SAMBA_SMBREADER="$(secret samba-smbreader)"

for user in smbuser smbreader; do
    id -u "$user" >/dev/null 2>&1 || adduser -D -H -s /sbin/nologin "$user"
done
printf '%s\n%s\n' "$LAB_SAMBA_SMBUSER" "$LAB_SAMBA_SMBUSER" | smbpasswd -a -s smbuser >/dev/null
printf '%s\n%s\n' "$LAB_SAMBA_SMBREADER" "$LAB_SAMBA_SMBREADER" | smbpasswd -a -s smbreader >/dev/null

mkdir -p /srv/samba/secure/sub /srv/samba/plain /srv/samba/readonly
printf 'secure share fixture\n' > /srv/samba/secure/hello.txt
printf 'unicode fixture\n' > '/srv/samba/secure/Überblick.txt'
printf 'nested fixture\n' > /srv/samba/secure/sub/nested.txt
printf 'plain share fixture\n' > /srv/samba/plain/hello.txt
printf 'read-only fixture\n' > /srv/samba/readonly/read-only.txt
chown -R smbuser:smbuser /srv/samba/secure /srv/samba/plain
chmod 0750 /srv/samba/secure /srv/samba/plain
chmod 0755 /srv/samba/readonly
chmod 0644 /srv/samba/readonly/read-only.txt

exec smbd --foreground --no-process-group --debug-stdout --configfile=/etc/samba/smb.conf
