#!/bin/sh
# Checks that scripts/build-release-binaries.sh builds only committed
# files: an untracked Go file with an init function and an untracked
# static file are planted into a copy of the checkout, and neither may
# reach the release binary.
#
#   tests/release/check-untracked.sh
set -eu

root=$(cd -- "$(dirname -- "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
marker=planted-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')

git -C "$root" archive --format=tar HEAD | tar -x -C "$work"
cd "$work"
git init -q
git add -A
git -c user.name=release-check -c user.email=release-check@invalid commit -qm snapshot

cat >internal/buildinfo/zz_planted.go <<GO
package buildinfo

import "os"

func init() { os.Stderr.WriteString("$marker\n") }
GO
printf '%s\n' "$marker" >static/zz_planted.txt
printf '%s\n' "$marker" >zz_planted_root.txt

if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    echo "check-untracked: the planted files must be untracked" >&2
    exit 1
fi

scripts/build-release-binaries.sh 0.0.0-check >/dev/null

host=$(uname -m)
case $host in
x86_64) host=amd64 ;;
aarch64) host=arm64 ;;
esac
fail=0
for arch in amd64 arm64; do
    out=$work/out-$arch
    mkdir "$out"
    tar -xzf "dist/webssh-0.0.0-check-linux-$arch.tar.gz" -C "$out"
    if grep -rq "$marker" "$out"; then
        echo "check-untracked: the $arch archive contains a planted file" >&2
        fail=1
    fi
    if [ "$arch" = "$host" ]; then
        got=$("$out/webssh-0.0.0-check-linux-$arch/webssh" version 2>&1)
        case $got in
        *"$marker"*)
            echo "check-untracked: the binary ran planted code" >&2
            fail=1
            ;;
        esac
    fi
done
[ "$fail" -eq 0 ] || exit 1
echo "check-untracked: no planted file reached the release binaries"
