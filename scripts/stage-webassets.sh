#!/bin/sh
# Copy static/ into internal/httpapi/webassets so the Go build can embed
# it. Run from anywhere; the copy is replaced as a whole, so files removed
# from static/ do not linger. The theme background PNG originals and their
# README are authoring sources: pages use the WebP derivatives at the same
# resolution, and the Python image leaves them out as well. Development builds may use -tags devfs
# instead, which reads static/ directly.
set -eu

cd -- "$(dirname -- "$0")/.."

if [ ! -d static ]; then
    echo "stage-webassets: static/ not found" >&2
    exit 1
fi

rm -rf internal/httpapi/webassets
mkdir -p internal/httpapi/webassets
cp -R static/. internal/httpapi/webassets/
rm -f internal/httpapi/webassets/images/theme-backgrounds/*.png \
    internal/httpapi/webassets/images/theme-backgrounds/README.md
