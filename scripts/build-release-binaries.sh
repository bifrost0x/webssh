#!/bin/sh
# Builds the release binaries for Linux (amd64, arm64) from a clean checkout:
#
#   scripts/build-release-binaries.sh 3.4.0
#
# Writes dist/webssh-<version>-linux-<arch>.tar.gz, each with the binary,
# LICENSE, NOTICE and THIRD-PARTY-NOTICES, and dist/SHA256SUMS. The binary
# carries the version and the full commit id (internal/buildinfo); the
# archives are reproducible: same commit and toolchain, same bytes.
# Windows and macOS have no release binaries (decision of 27.11.2026).
set -eu

cd -- "$(dirname -- "$0")/.."

version=${1:-}
if ! printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'; then
    echo "usage: $0 <version>, for example 3.4.0 or 3.4.0-rc.1" >&2
    exit 2
fi
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    echo "build-release-binaries: the checkout has uncommitted changes" >&2
    exit 1
fi
revision=$(git rev-parse HEAD)
epoch=$(git log -1 --format=%ct HEAD)
go=${GO:-go}
pkg=github.com/bifrost0x/webssh/internal/buildinfo

scripts/stage-webassets.sh
rm -rf dist
mkdir -p dist
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

for arch in amd64 arm64; do
    name=webssh-$version-linux-$arch
    mkdir "$work/$name"
    CGO_ENABLED=0 GOOS=linux GOARCH=$arch GOFLAGS=-mod=readonly "$go" build \
        -trimpath -buildvcs=false \
        -ldflags "-s -w -buildid= -X $pkg.version=$version -X $pkg.revision=$revision" \
        -o "$work/$name/webssh" ./cmd/webssh
    cp LICENSE NOTICE THIRD-PARTY-NOTICES "$work/$name/"
    chmod 0755 "$work/$name/webssh"
    chmod 0644 "$work/$name/LICENSE" "$work/$name/NOTICE" "$work/$name/THIRD-PARTY-NOTICES"
    tar -C "$work" --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
        --format=gnu -cf - "$name" | gzip -n -9 >"dist/$name.tar.gz"
done

# The binary for this machine must report the version and the revision.
host=$(uname -m)
case $host in
x86_64) host=amd64 ;;
aarch64) host=arm64 ;;
esac
if [ -x "$work/webssh-$version-linux-$host/webssh" ]; then
    got=$("$work/webssh-$version-linux-$host/webssh" version)
    short=$(printf '%.7s' "$revision")
    if [ "$got" != "$version ($short)" ]; then
        echo "build-release-binaries: version reports \"$got\", want \"$version ($short)\"" >&2
        exit 1
    fi
fi

(cd dist && sha256sum -- *.tar.gz >SHA256SUMS)
cat dist/SHA256SUMS
