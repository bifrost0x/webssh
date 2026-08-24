#!/bin/sh
set -eu

useradd --no-create-home --shell /usr/sbin/nologin smbuser
printf '%s\n%s\n' 'Smb-Lab-Only-42!' 'Smb-Lab-Only-42!' | smbpasswd -a -s smbuser

mkdir -p /srv/samba/docs/denied /srv/samba/denied
printf '%s\n' 'SMB integration fixture' > /srv/samba/docs/hello.txt
printf '%s\n' 'Unicode fixture' > '/srv/samba/docs/Überblick.txt'
ln -s /etc/passwd /srv/samba/docs/escape-link
chown -R smbuser:smbuser /srv/samba/docs
chmod 700 /srv/samba/docs
chmod 000 /srv/samba/docs/denied
chmod 700 /srv/samba/denied

# Writable file in a sticky, root-owned directory: smbuser may modify the file
# but cannot delete or rename it. This exercises the explicit non-atomic editor
# fallback without weakening the normal atomic-replacement path.
mkdir /srv/samba/docs/atomic-denied
printf '%s\n' 'Original protected fixture' > /srv/samba/docs/atomic-denied/replace-denied.txt
chown root:root /srv/samba/docs/atomic-denied /srv/samba/docs/atomic-denied/replace-denied.txt
chmod 1733 /srv/samba/docs/atomic-denied
chmod 666 /srv/samba/docs/atomic-denied/replace-denied.txt

exec smbd --foreground --no-process-group --debug-stdout --configfile=/etc/samba/smb.conf
