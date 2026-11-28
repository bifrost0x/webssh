#!/bin/sh
# Runs the kernel-facing tests of internal/netpolicy and
# internal/ssh/tailscale inside a network namespace, as an unprivileged
# user without capabilities.
#   lab      joins lab-ts-node, the Tailscale stand-in of the test lab
#            (tests/lab); nothing in the lab is changed
#   crafted  an own namespace built by netns-crafted.sh in a throwaway
#            holder container; NETNS_TOOLS_IMAGE names an image with
#            iproute2 (default: the lab's webssh-lab/tools:local)
# In lab mode it also shows, with the Python release's socket options,
# that IP_UNICAST_IF does not hold a TCP connection on tailscale0.
#
# The route answers of the Python release are recorded per mode in
# python_routes.json, and TestPythonRoutesInNamespace compares Go with
# them. WEBSSH_PYTHON_ORACLE (internal/oracletest) selects the mode:
#   unset    replay the recording; Python is not needed
#   live     ask the Python release (app/tailscale_ssh.py under
#            WEBSSH_PYTHON_ROOT) and require the recorded answers
#   record   ask it and write the answers into the recording; needs
#            WEBSSH_PYTHON_ORACLE_SOURCE (scripts/record-python-oracles.sh)
set -eu
mode=${1:?usage: netns-test.sh lab|crafted}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
lab_json=${WEBSSH_LAB_JSON:-$root/tests/lab/runtime/lab.json}
oracle=${WEBSSH_PYTHON_ORACLE:-}
pyroot=${WEBSSH_PYTHON_ROOT:-$root}
recording="$here/python_routes.json"
python_image=python:3.15-alpine@sha256:0f9552bb28711333da16915ec146f5e6bb44a7fdac9ced15dc17c2e0206346dd
alpine_image=alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
case "$oracle" in
"" | live | record) ;;
*) echo "netns-test.sh: WEBSSH_PYTHON_ORACLE=$oracle; want unset, live or record" >&2; exit 2 ;;
esac
if [ -n "$oracle" ] && [ ! -f "$pyroot/app/tailscale_ssh.py" ]; then
	echo "netns-test.sh: WEBSSH_PYTHON_ORACLE=$oracle needs the Python release in $pyroot (WEBSSH_PYTHON_ROOT)" >&2
	exit 1
fi
out=$(mktemp -d)
chmod 755 "$out"
holder=""
cleanup() {
	[ -n "$holder" ] && docker rm -f "$holder" >/dev/null 2>&1
	rm -f "$out/netpolicy.test" "$out/tailscale.test" "$out/py-routes.json" "$out/python_routes.json"
	rmdir "$out"
}
trap cleanup EXIT
(cd "$root" && CGO_ENABLED=0 go test -c -o "$out/netpolicy.test" ./internal/netpolicy)
(cd "$root" && CGO_ENABLED=0 go test -c -o "$out/tailscale.test" ./internal/ssh/tailscale)
# The addresses whose route the Python release and Go must agree on.
addresses="100.100.100.10 100.64.0.1 100.100.100.2 8.8.8.8 127.0.0.1 fd7a:115c:a1e0::1 fd7a:115c:a1e0:b1a::a00:1
100.100.1.1 fd7a:115c:a1e0::9 100.80.0.7 100.90.0.1 100.91.0.1 100.100.1.2 192.0.2.10 198.51.100.1 ::ffff:100.100.100.10"
# record_routes writes the fresh answers of this mode into the recording.
# Unchanged answers keep the recording, header included.
record_routes() {
	version=$(docker run --rm --network none "$python_image" python3 -I -c \
		'import platform; print(platform.python_implementation(), platform.python_version())')
	: "${WEBSSH_PYTHON_ORACLE_SOURCE:?recording needs WEBSSH_PYTHON_ORACLE_SOURCE (scripts/record-python-oracles.sh)}"
	if [ -f "$recording" ]; then cp "$recording" "$out/python_routes.json"; else echo '{}' >"$out/python_routes.json"; fi
	jq -S --arg mode "$mode" --arg python "$version ($python_image)" --arg source "$WEBSSH_PYTHON_ORACLE_SOURCE" \
		--slurpfile routes "$out/py-routes.json" \
		'if .routes[$mode] == $routes[0] then . else .oracle = {python: $python, source: $source, recorder: "scripts/record-python-oracles.sh"} | .routes[$mode] = $routes[0] end' \
		"$out/python_routes.json" >"$recording"
}
run_in() {
	live_env=""
	if [ -n "$oracle" ]; then
		# shellcheck disable=SC2086
		docker run --rm --network "container:$1" --cap-drop ALL --read-only --user 65534:65534 \
			-v "$here/python_routes.py:/p/routes.py:ro" -v "$pyroot/app/tailscale_ssh.py:/p/tailscale_ssh.py:ro" \
			"$python_image" python3 -I /p/routes.py /p/tailscale_ssh.py $addresses > "$out/py-routes.json"
		[ "$oracle" = record ] && record_routes
		live_env="-e WEBSSH_PY_ROUTES=/t/py-routes.json"
	fi
	cp "$recording" "$out/python_routes.json"
	# shellcheck disable=SC2086 # live_env is empty or one option with its value
	docker run --rm --network "container:$1" --cap-drop ALL --read-only --user 65534:65534 \
		-e WEBSSH_NETNS="$mode" -e WEBSSH_PY_ROUTES_RECORDING=/t/python_routes.json $live_env -v "$out:/t:ro" "$alpine_image" \
		/t/netpolicy.test -test.v -test.count=1 -test.run 'Namespace|LookupRoute|DialInterface|PythonRoutes'
	if [ "$mode" = lab ]; then
		fingerprints=$(jq -r '.services.tailscale.target.host_key_fingerprints | [.[]] | join(",")' "$lab_json")
		modern=$(docker inspect -f '{{(index .NetworkSettings.Networks "webssh-lab_front").IPAddress}}' webssh-lab-ssh-modern-1)
		docker run --rm --network "container:$1" --cap-drop ALL --read-only --user 65534:65534 \
			-e WEBSSH_NETNS="$mode" -e WEBSSH_TS_FINGERPRINTS="$fingerprints" -e WEBSSH_LAB_SSH_MODERN="$modern:22" \
			-v "$out:/t:ro" "$alpine_image" /t/tailscale.test -test.v -test.count=1 -test.run 'Lab'
		echo "### Python socket options (app/network_policy.py) against ssh-modern on eth0"
		docker run --rm --network "container:$1" --cap-drop ALL --read-only --user 65534:65534 \
			-e MODERN="$modern" "$python_image" python3 -I -c '
import os, socket
target = (os.environ["MODERN"], 22)
def attempt(label, configure):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        configure(s)
        s.connect(target)
        print(label, "CONNECTED", s.recv(32))
    except OSError as error:
        print(label, "REFUSED", type(error).__name__, error.strerror or "")
    finally:
        s.close()
index = socket.htonl(socket.if_nametoindex("tailscale0"))
attempt("IP_UNICAST_IF (Python release):", lambda s: s.setsockopt(socket.IPPROTO_IP, 50, index))
attempt("SO_BINDTODEVICE (Go):          ", lambda s: s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"tailscale0"))
'
	fi
}
case "$mode" in
lab)
	run_in lab-ts-node
	;;
crafted)
	holder="webssh-netns-$$"
	docker run -d --name "$holder" --network none --cap-drop ALL --cap-add NET_ADMIN --read-only \
		--sysctl net.ipv6.conf.all.disable_ipv6=0 --sysctl net.ipv6.conf.default.disable_ipv6=0 \
		-v "$here:/s:ro" --entrypoint /s/netns-crafted.sh "${NETNS_TOOLS_IMAGE:-webssh-lab/tools:local}" sleep 600 >/dev/null
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		docker exec "$holder" ip rule show 2>/dev/null | grep -q 'lookup 52' && break
		sleep 0.5
	done
	run_in "$holder"
	;;
*) echo "unknown mode $mode" >&2; exit 2 ;;
esac
