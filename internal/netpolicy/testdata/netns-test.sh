#!/bin/sh
# Runs the kernel-facing route tests of internal/netpolicy inside a network
# namespace, as an unprivileged user without capabilities.
#   lab      joins lab-ts-node, the Tailscale stand-in of the test lab
#            (tests/lab); nothing in the lab is changed
#   crafted  an own namespace built by netns-crafted.sh in a throwaway
#            holder container; NETNS_TOOLS_IMAGE names an image with
#            iproute2 (default: the lab's webssh-lab/tools:local)
set -eu
mode=${1:?usage: netns-test.sh lab|crafted}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out=$(mktemp -d)
chmod 755 "$out"
holder=""
cleanup() {
	[ -n "$holder" ] && docker rm -f "$holder" >/dev/null 2>&1
	rm -f "$out/netpolicy.test"
	rmdir "$out"
}
trap cleanup EXIT
(cd "$root" && CGO_ENABLED=0 go test -c -o "$out/netpolicy.test" ./internal/netpolicy)
run_in() {
	docker run --rm --network "container:$1" --cap-drop ALL --read-only --user 65534:65534 \
		-e WEBSSH_NETNS="$mode" -v "$out:/t:ro" alpine:3 \
		/t/netpolicy.test -test.v -test.count=1 -test.run 'Namespace|LookupRoute'
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
