#!/bin/sh
# Starts a throwaway OpenSSH server from the lab image webssh-lab/ssh:local
# with a pre-authentication banner and runs TestBannerServer against it. The
# shared lab (tests/lab) has no banner and is not touched. BANNER_IMAGE
# selects another build of tests/lab/images/ssh, as in CI.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../../.." && pwd)
name="webssh-banner-$$"
image="${BANNER_IMAGE:-webssh-lab/ssh:local}"
password=$(head -c 18 /dev/urandom | base64 | tr -d '/+=')
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker run -d --name "$name" -p 127.0.0.1::22 -e PW="$password" --entrypoint /bin/sh \
	"$image" -c '
set -eu
ssh-keygen -q -t ed25519 -N "" -f /etc/ssh/banner_host_key
adduser -D -s /bin/sh pwuser
printf "pwuser:%s\n" "$PW" | chpasswd
printf "Authorized use only.\n\033[31mWarning:\033[0m Gr\303\274\303\237e \a\n" > /etc/ssh/banner
cat > /etc/ssh/banner_config <<CFG
Port 22
HostKey /etc/ssh/banner_host_key
Banner /etc/ssh/banner
PasswordAuthentication yes
KbdInteractiveAuthentication no
AllowUsers pwuser
PerSourcePenalties no
CFG
exec /usr/sbin/sshd -D -e -f /etc/ssh/banner_config' >/dev/null
port=$(docker port "$name" 22/tcp | head -n1 | sed 's/.*://')
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
	docker logs "$name" 2>&1 | grep -q "Server listening" && break
	sleep 0.5
done
cd "$root"
WEBSSH_BANNER_ADDR="127.0.0.1:$port" WEBSSH_BANNER_PASSWORD="$password" \
	go test -tags lab -count=1 -v -run TestBannerServer ./internal/ssh/client
