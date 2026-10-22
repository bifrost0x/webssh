#!/usr/bin/env bash
set -euo pipefail

architecture="${1:-}"
if [[ "${GITHUB_EVENT_NAME:-}" != pull_request ]] ||
   [[ "$architecture" != amd64 && "$architecture" != arm64 ]] ||
   [[ ! "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ ]] ||
   [[ ! "${GITHUB_RUN_ID:-}" =~ ^[0-9]+$ ]] ||
   [[ ! "${GITHUB_RUN_ATTEMPT:-}" =~ ^[0-9]+$ ]]; then
    echo 'Expected a pull request, supported architecture and valid run metadata.' >&2
    exit 2
fi

# Native hosted runners already provide Docker's default BuildKit builder.
# Keep OS packages fresh without waiting for a remote cache export before scanning.
export DOCKER_BUILDKIT=1
docker build --pull --platform "linux/$architecture" \
    --tag "webssh-security:$GITHUB_SHA" \
    --build-arg "VCS_REF=$GITHUB_SHA" \
    --build-arg "OS_PACKAGE_REFRESH=$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT" .

if [[ "$architecture" == arm64 ]]; then
    docker image save --output /tmp/webssh-arm64.tar "webssh-security:$GITHUB_SHA"
fi
