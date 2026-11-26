#!/usr/bin/env bash
# Container checks for the Go image (deploy/docker/Dockerfile).
#
#   tests/image/check.sh            build both targets, then check
#   BUILD=0 tests/image/check.sh    check existing webssh-go:m1 and :m1-debug
#   TRIVY=1 tests/image/check.sh    also scan the release image with Trivy
#
# Every run uses the restrictions of docker-compose.hardened.yml. The debug
# image (the same image plus BusyBox) inspects files the release image has
# no tools for. Only containers and volumes named webssh-go-check-* are
# created, and removed again.
set -uo pipefail
cd "$(dirname "$0")/../.."

IMG=${IMG:-webssh-go:m1}
DEBUG_IMG=${DEBUG_IMG:-webssh-go:m1-debug}
BUSYBOX=busybox:1.37-musl@sha256:f6a95d611e0a8780fabdb2aec43e31275b2720dfefa3e41b16835bfc42454478
TRIVY_IMG=aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c
P=webssh-go-check
HARD=(--read-only --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 512 --memory 2g
      --tmpfs /tmp:rw,noexec,nosuid,nodev,size=128m,mode=1777)
pass=0 fail=0
BIND=""

ok()    { echo "PASS $*"; pass=$((pass + 1)); }
bad()   { echo "FAIL $*"; fail=$((fail + 1)); }
check() { local name=$1; shift; if "$@"; then ok "$name"; else bad "$name"; fi; }

cleanup() {
  docker rm -f "$P-run" "$P-port" "$P-u99" "$P-u99b" "$P-tz" >/dev/null 2>&1
  docker volume rm -f "$P-data" "$P-data99" >/dev/null 2>&1
  if [ -n "$BIND" ] && [ -d "$BIND" ]; then
    # The bind directory belongs to 99:100 inside the user namespace; remove
    # its content from a container, then the now empty directory.
    docker run --rm -v "$BIND:/v" "$BUSYBOX" rm -rf /v/data >/dev/null 2>&1
    rmdir "$BIND"
  fi
}
trap cleanup EXIT
cleanup

if [ "${BUILD:-1}" = 1 ]; then
  rev=$(git rev-parse HEAD)
  docker build -q -f deploy/docker/Dockerfile --target release --build-arg VCS_REF="$rev" -t "$IMG" . >/dev/null || exit 1
  docker build -q -f deploy/docker/Dockerfile --target debug --build-arg VCS_REF="$rev" -t "$DEBUG_IMG" . >/dev/null || exit 1
fi

wait_healthy() {
  local c=$1 i st
  for i in $(seq 60); do
    st=$(docker inspect -f '{{.State.Health.Status}}' "$c" 2>/dev/null)
    [ "$st" = healthy ] && return 0
    [ "$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" = true ] || return 1
    sleep 0.5
  done
  return 1
}

# Runs a BusyBox command on the data volume with the same restrictions.
inspect_volume() { docker run --rm "${HARD[@]}" -v "$1:/app/data" --entrypoint /bin/sh "$DEBUG_IMG" -c "$2"; }

echo "== 1 image configuration"
cfg=$(docker image inspect "$IMG" -f '{{.Config.User}}|{{json .Config.Entrypoint}}|{{json .Config.Cmd}}|{{json .Config.Healthcheck.Test}}')
echo "$cfg"
check "user 1000:1000, exec-form healthcheck, serve on 0.0.0.0:5000" \
  test "$cfg" = '1000:1000|["/app/webssh"]|["serve","--bind","0.0.0.0:5000"]|["CMD","/app/webssh","healthcheck"]'
check "release image has no shell" bash -c "! docker run --rm --entrypoint /bin/sh '$IMG' -c true >/dev/null 2>&1"

echo "== 2 default user, hardened, named volume"
docker run -d --name "$P-run" "${HARD[@]}" --health-interval 1s -v "$P-data:/app/data" "$IMG" >/dev/null
check "healthy via 'webssh healthcheck' without a shell" wait_healthy "$P-run"
# A separate container publishes the port: with rootless Docker, restarting
# a container with an ephemeral host port can fail in RootlessKit's port
# allocation ("address already in use"), which says nothing about the image.
hostport=""
for _ in 1 2 3; do
  docker rm -f "$P-port" >/dev/null 2>&1
  if docker run -d --name "$P-port" "${HARD[@]}" -p 127.0.0.1::5000 "$IMG" >/dev/null; then
    hostport=$(docker port "$P-port" 5000/tcp | head -1)
    break
  fi
done
check "/ready answers 200 from the host" bash -c "wait_() { for _ in \$(seq 40); do curl -sf -o /dev/null 'http://$hostport/ready' && return 0; sleep 0.25; done; return 1; }; wait_"
docker rm -f "$P-port" >/dev/null
pid=$(docker inspect -f '{{.State.Pid}}' "$P-run")
grep -E '^(Uid|Gid|CapEff|CapBnd|NoNewPrivs)' "/proc/$pid/status"
check "PID 1 is the binary, no capabilities, no_new_privs" bash -c "
  [ \"\$(tr '\0' ' ' < /proc/$pid/cmdline)\" = '/app/webssh serve --bind 0.0.0.0:5000 ' ] &&
  grep -q '^CapEff:[[:space:]]*0000000000000000' /proc/$pid/status &&
  grep -q '^CapBnd:[[:space:]]*0000000000000000' /proc/$pid/status &&
  grep -q '^NoNewPrivs:[[:space:]]*1' /proc/$pid/status"
host_uid=$(awk -v id=1000 '$1 <= id && id < $1 + $3 { print $2 + id - $1 }' "/proc/$pid/uid_map")
check "process runs as container uid 1000" bash -c "awk '/^Uid/ { exit !(\$2 == $host_uid) }' /proc/$pid/status"
check "root file system is read-only, /app/data and /tmp are writable" \
  inspect_volume "$P-data" '! touch /app/x 2>/dev/null && ! touch /etc/x 2>/dev/null && touch /app/data/.w /tmp/.w && rm /app/data/.w'
check "/app/data, logs and keys are 0700 and owned by 1000:1000" \
  inspect_volume "$P-data" 'for d in /app/data /app/data/logs /app/data/keys; do [ "$(stat -c "%a %u:%g" $d)" = "700 1000:1000" ] || exit 1; done'
check "binary root-owned 0555, entrypoint.sh links to it, CA bundle present" \
  inspect_volume "$P-data" '[ "$(stat -c "%a %u:%g" /app/webssh)" = "555 0:0" ] && [ "$(readlink /app/entrypoint.sh)" = webssh ] && [ "$(grep -c "BEGIN CERTIFICATE" /etc/ssl/certs/ca-certificates.crt)" -gt 100 ]'

echo "== 3 graceful shutdown as PID 1"
start=$(date +%s%N)
docker stop -t 10 "$P-run" >/dev/null
ms=$(( ($(date +%s%N) - start) / 1000000 ))
code=$(docker inspect -f '{{.State.ExitCode}}' "$P-run")
echo "docker stop took ${ms} ms, exit code $code"
check "SIGTERM stops within 2 s with exit 0 and logs shutdown complete" bash -c \
  "[ $ms -lt 2000 ] && [ $code -eq 0 ] && docker logs '$P-run' 2>&1 | grep -q 'shutdown complete'"
docker start "$P-run" >/dev/null || docker inspect -f '{{.State.Error}}' "$P-run"
check "restart on the same volume becomes healthy" wait_healthy "$P-run"
docker kill -s INT "$P-run" >/dev/null
for _ in $(seq 20); do [ "$(docker inspect -f '{{.State.Running}}' "$P-run")" = false ] && break; sleep 0.25; done
check "SIGINT also exits 0" test "$(docker inspect -f '{{.State.Running}} {{.State.ExitCode}}' "$P-run")" = "false 0"
docker rm -f "$P-run" >/dev/null

echo "== 4 --user 99:100 (Unraid)"
docker run -d --name "$P-u99" "${HARD[@]}" --user 99:100 -v "$P-data99:/app/data" "$IMG" >/dev/null
for _ in $(seq 20); do [ "$(docker inspect -f '{{.State.Running}}' "$P-u99")" = false ] && break; sleep 0.25; done
docker logs "$P-u99" 2>&1 | tail -1
check "fresh named volume (seeded 1000:1000) refuses with the chown hint" bash -c \
  "[ \"\$(docker inspect -f '{{.State.ExitCode}}' '$P-u99')\" = 1 ] && docker logs '$P-u99' 2>&1 | grep -q 'chown -R 99:100 <host directory>'"
docker rm -f "$P-u99" >/dev/null
# Unraid bind-mounts appdata folders it created for 99:100; Docker never
# seeds a bind mount from the image.
BIND=$(mktemp -d "${TMPDIR:-/tmp}/webssh-go-check.XXXXXX")
docker run --rm -v "$BIND:/v" "$BUSYBOX" sh -c 'mkdir /v/data && chown 99:100 /v/data && chmod 755 /v/data'
docker run -d --name "$P-u99b" "${HARD[@]}" --health-interval 1s --user 99:100 -v "$BIND/data:/app/data" "$IMG" >/dev/null
check "99:100 with a 99:100-owned bind mount becomes healthy, mode 0700" bash -c \
  "wait_() { for _ in \$(seq 60); do [ \"\$(docker inspect -f '{{.State.Health.Status}}' '$P-u99b')\" = healthy ] && return 0; sleep 0.5; done; return 1; }; wait_ &&
   docker logs '$P-u99b' 2>&1 | grep -q 'access=\"mode=0700 runtime_user=99:100\"'"
docker rm -f "$P-u99b" >/dev/null

echo "== 5 time zones (no zoneinfo in the image)"
tz_log() {
  docker run -d --name "$P-tz" "${HARD[@]}" -e TZ="$1" "$IMG" >/dev/null
  for _ in $(seq 40); do docker logs "$P-tz" 2>&1 | grep -q 'msg=ready' && break; sleep 0.25; done
  docker logs "$P-tz" 2>&1
  docker rm -f "$P-tz" >/dev/null
}
berlin=$(tz_log Europe/Berlin)
invalid=$(tz_log Invalid/Zone)
echo "$invalid" | grep 'time zone' || true
check "Europe/Berlin loads from the embedded database, local times carry +01:00/+02:00, Invalid/Zone is reported" bash -c \
  "! grep -q 'time zone not applied' <<<\"\$1\" && grep -q 'time=[0-9T:.-]*+0[12]:00' <<<\"\$1\" && grep -q 'time zone not applied' <<<\"\$2\"" _ "$berlin" "$invalid"

echo "== 6 command forms"
out=$(docker run --rm "${HARD[@]}" --entrypoint /app/entrypoint.sh "$IMG" flask --app start:app create-admin --username check 2>&1); code=$?
echo "$out (exit $code)"
other=$(docker run --rm "${HARD[@]}" --entrypoint /app/entrypoint.sh "$IMG" sh -c id 2>&1); other_code=$?
check "/app/entrypoint.sh takes the flask form and refuses any other argv" bash -c \
  "[ $code -ne 0 ] && grep -q 'create-admin' <<<\"\$1\" && [ $other_code -eq 2 ] && grep -q 'no shell' <<<\"\$2\"" _ "$out" "$other"
version=$(docker run --rm "${HARD[@]}" "$IMG" version)
label=$(docker image inspect "$IMG" -f '{{index .Config.Labels "org.opencontainers.image.revision"}}')
echo "version: $version, revision label: $label"
check "version reports the release version and the revision of the label" bash -c \
  "[[ \"\$1\" == 3.4.0-m1* ]] && { [ \"\$2\" = unknown ] || [[ \"\$1\" == *\"(\${2:0:7})\" ]]; }" _ "$version" "$label"

if [ "${TRIVY:-0}" = 1 ]; then
  echo "== 7 Trivy"
  TAR=$(mktemp "${TMPDIR:-/tmp}/webssh-go-check.XXXXXX.tar")
  docker save -o "$TAR" "$IMG"
  check "Trivy: no vulnerabilities, secrets or misconfigurations in the release image" \
    docker run --rm -v "$TAR:/image.tar:ro" "$TRIVY_IMG" image --quiet --exit-code 1 \
      --scanners vuln,secret,misconfig --input /image.tar
  rm -f "$TAR"
fi

echo "== summary: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
