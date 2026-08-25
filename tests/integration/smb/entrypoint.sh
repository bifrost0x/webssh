#!/bin/sh
set -eu

if ! id -u smbuser >/dev/null 2>&1; then
    useradd --no-create-home --shell /usr/sbin/nologin smbuser
fi
printf '%s\n%s\n' 'Smb-Lab-Only-42!' 'Smb-Lab-Only-42!' | smbpasswd -a -s smbuser

mkdir -p /srv/samba/docs/denied /srv/samba/denied /srv/samba/readonly
printf '%s\n' 'SMB integration fixture' > /srv/samba/docs/hello.txt
printf '%s\n' 'Unicode fixture' > '/srv/samba/docs/Überblick.txt'
ln -sf /etc/passwd /srv/samba/docs/escape-link
chown -R smbuser:smbuser /srv/samba/docs
chmod 700 /srv/samba/docs
chmod 000 /srv/samba/docs/denied
chmod 700 /srv/samba/denied
printf '%s\n' 'Read-only integration fixture' > /srv/samba/readonly/read-only.txt
chown -R root:root /srv/samba/readonly
chmod 755 /srv/samba/readonly
chmod 644 /srv/samba/readonly/read-only.txt

# Writable file in a sticky, root-owned directory: smbuser may modify the file
# but cannot delete or rename it. This exercises the explicit recoverable-swap
# consent path and verifies that a denied swap leaves the original untouched.
mkdir -p /srv/samba/docs/atomic-denied
printf '%s\n' 'Original protected fixture' > /srv/samba/docs/atomic-denied/replace-denied.txt
chown root:root /srv/samba/docs/atomic-denied /srv/samba/docs/atomic-denied/replace-denied.txt
chmod 1733 /srv/samba/docs/atomic-denied
chmod 666 /srv/samba/docs/atomic-denied/replace-denied.txt

exec smbd --foreground --no-process-group --debug-stdout --configfile=/etc/samba/smb.conf
