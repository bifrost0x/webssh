#!/usr/bin/env bash
# Upgrade of a 3.3 installation to the image under test, and the way back.
#
#   IMG=webssh:local tests/image/upgrade.sh
#
# The last Python release writes a data volume (an administrator from its
# CLI, then a first start), the image under test starts on the same
# volumes, migrates and keeps the account, and the Python release starts
# again on them afterwards: the migration leaves the 3.3 data as it was.
# PREVIOUS is the published 3.3.0 index until 3.3.1 is published; then its
# digest replaces it. Only containers and volumes named
# webssh-upgrade-check* are created, and removed again.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1

IMG=${IMG:-webssh:local}
PREVIOUS=${PREVIOUS:-ghcr.io/bifrost0x/webssh@sha256:4979ba1bdd1f6856c9363cc54fbf63218d6a258e418db9dcb4a35655eacee20f}
BUSYBOX=busybox:1.38-musl@sha256:80e38f9a1b39188b8bdb28879178edb322a4402b081a9aedda1924609decd6f6
P=webssh-upgrade-check
ADMIN=upgrade_admin
MOUNTS=(-v "$P-data:/app/data" -v "$P-recovery:/app/recovery")
ENVS=(-e BACKUP_TEMP_DIR=/app/recovery -e BACKUP_RECOVERY_DURABLE=true -e SESSION_COOKIE_SECURE=false)
pass=0 fail=0

ok()    { echo "PASS $*"; pass=$((pass + 1)); }
bad()   { echo "FAIL $*"; fail=$((fail + 1)); }
check() { local name=$1; shift; if "$@"; then ok "$name"; else bad "$name"; fi; }

cleanup() {
  docker rm -f "$P-old" "$P-new" "$P-back" >/dev/null 2>&1
  docker volume rm -f "$P-data" "$P-recovery" >/dev/null 2>&1
}
trap cleanup EXIT
cleanup

wait_healthy() {
  local c=$1
  for _ in $(seq 120); do
    [ "$(docker inspect -f '{{.State.Health.Status}}' "$c" 2>/dev/null)" = healthy ] && return 0
    [ "$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" = true ] || return 1
    sleep 0.5
  done
  return 1
}

stop() {
  docker stop -t 40 "$1" >/dev/null && [ "$(docker inspect -f '{{.State.ExitCode}}' "$1")" = 0 ]
}

# A file listing of the 3.3 data with mode, owner, size and content digest.
# logs/ is left out: both releases append to the same security audit log
# (invariant I-10).
listing() {
  docker run --rm -v "$P-data:/v:ro" "$BUSYBOX" sh -c \
    'cd /v && find . -path ./logs -prune -o -type f -print | sort | while read -r f; do
       printf "%s %s %s\n" "$(stat -c "%a %u:%g %s" "$f")" "$(sha256sum "$f" | cut -c1-64)" "$f"; done'
}

password="Upgrade-$RANDOM$RANDOM-$RANDOM$RANDOM"
echo "== 1 the Python release writes its data"
docker pull -q "$PREVIOUS" >/dev/null || exit 1
created=$(printf '%s\n%s\n' "$password" "$password" |
  docker run --rm -i "${ENVS[@]}" "${MOUNTS[@]}" "$PREVIOUS" flask --app start:app create-admin --username "$ADMIN" 2>&1)
created_code=$?
echo "$created" | tail -1
check "the 3.3 CLI creates the administrator" bash -c "[ $created_code -eq 0 ] && grep -q -E 'Administrator (created|ready)' <<<\"\$1\"" _ "$created"
docker run -d --name "$P-old" "${ENVS[@]}" "${MOUNTS[@]}" --health-interval 1s "$PREVIOUS" >/dev/null
check "3.3 starts healthy on its volumes" wait_healthy "$P-old"
check "3.3 stops with exit 0" stop "$P-old"
before=$(listing)

echo "== 2 the image under test starts on the same volumes"
docker run -d --name "$P-new" "${ENVS[@]}" "${MOUNTS[@]}" --health-interval 1s "$IMG" >/dev/null
check "the new image migrates and becomes healthy" wait_healthy "$P-new"
docker logs "$P-new" 2>&1 | grep -i -m 3 'migrat' || true
check "the new image stops with exit 0" stop "$P-new"
reset=$(printf '%s\n%s\n' "$password-new" "$password-new" |
  docker run --rm -i "${ENVS[@]}" "${MOUNTS[@]}" "$IMG" reset-password --username "$ADMIN" 2>&1); reset_code=$?
printf 'x\nx\n' | docker run --rm -i "${ENVS[@]}" "${MOUNTS[@]}" "$IMG" reset-password --username nobody_here >/dev/null 2>&1; unknown_code=$?
echo "$reset" | tail -1
check "the migrated administrator exists in the new release, an unknown name does not" \
  bash -c "[ $reset_code -eq 0 ] && [ $unknown_code -ne 0 ]"
check "data and recovery stay 0700 and owned by 1000:1000" bash -c \
  "[ \"\$(docker run --rm -v $P-data:/d:ro -v $P-recovery:/r:ro $BUSYBOX stat -c '%a %u:%g' /d /r | tr '\\n' ' ')\" = '700 1000:1000 700 1000:1000 ' ]"
after=$(listing)
# Every file of 3.3 is still there with the same mode, owner and content;
# files the new release adds do not matter here.
check "the files of 3.3 are unchanged after the migration" bash -c \
  "[ -n \"\$1\" ] && ! grep -v -x -F -f <(printf '%s\n' \"\$2\") <<<\"\$1\"" _ "$before" "$after"

echo "== 3 the way back to 3.3"
docker run -d --name "$P-back" "${ENVS[@]}" "${MOUNTS[@]}" --health-interval 1s "$PREVIOUS" >/dev/null
check "3.3 starts healthy again on the migrated volumes" wait_healthy "$P-back"
check "3.3 stops with exit 0" stop "$P-back"
# Without a password file and stdin, create-admin only succeeds for an
# account that exists.
kept=$(docker run --rm "${ENVS[@]}" "${MOUNTS[@]}" "$PREVIOUS" flask --app start:app create-admin --username "$ADMIN" </dev/null 2>&1)
kept_code=$?
echo "$kept" | tail -1
check "3.3 still knows its administrator" bash -c "[ $kept_code -eq 0 ] && grep -q 'Administrator ready' <<<\"\$1\"" _ "$kept"

echo "== summary: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
