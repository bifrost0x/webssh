#!/bin/sh
# Accounts and keys come from the read-only per-run runtime at /lab.
set -eu
role="${LAB_SSH_ROLE:-standard}"
host="${LAB_SSH_HOST:?}"

install -d -m 0755 /etc/ssh/keys /etc/ssh/authorized_keys
for key in /lab/ssh/hostkeys/"$host"/ssh_host_*_key; do
    install -m 0600 "$key" /etc/ssh/keys/
    install -m 0644 "$key.pub" /etc/ssh/keys/
done

if [ "$role" = tailscale ]; then
    id -u tsuser >/dev/null 2>&1 || adduser -D -s /bin/sh tsuser
    passwd -d tsuser >/dev/null
    exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config_tailscale
fi

secret() { head -n1 "/lab/secrets/$1"; }
LAB_SSH_PWUSER="$(secret ssh-pwuser)"
LAB_SSH_KIUSER="$(secret ssh-kiuser)"
LAB_SSH_MFAUSER="$(secret ssh-mfauser)"
for user in pwuser keyuser kiuser mfauser; do
    id -u "$user" >/dev/null 2>&1 || adduser -D -s /bin/sh "$user"
done
# keyuser has no usable password; it only accepts public keys.
usermod -p '*' keyuser
printf 'pwuser:%s\nkiuser:%s\nmfauser:%s\n' \
    "$LAB_SSH_PWUSER" "$LAB_SSH_KIUSER" "$LAB_SSH_MFAUSER" | chpasswd

for user in keyuser mfauser; do
    install -m 0644 /lab/ssh/authorized_keys /etc/ssh/authorized_keys/"$user"
done
install -d -m 0700 /etc/lab-totp
for user in kiuser mfauser; do
    install -m 0400 /lab/ssh/"$user".google_authenticator /etc/lab-totp/"$user"
done
printf 'fixture for %s\n' "$host" > /home/pwuser/hello.txt
chown pwuser:pwuser /home/pwuser/hello.txt

/usr/sbin/sshd.pam -t
exec /usr/sbin/sshd.pam -D -e
