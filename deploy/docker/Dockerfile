# syntax=docker/dockerfile:1
#
# WebSSH (Go) on scratch. Build from the repository root:
#
#   docker build -f deploy/docker/Dockerfile --target release -t webssh:local .
#   docker build -f deploy/docker/Dockerfile --target debug -t webssh:local-debug .
#
# Published tags: the release target as <version>, <major>.<minor> and
# latest, the debug target as debug and <version>-debug (deploy/README.md).
#
# deploy/docker/Dockerfile.dockerignore limits the context to the Go module
# and the frontend assets. The binary is cross-compiled on the build platform
# (CGO_ENABLED=0), so an arm64 image needs no emulation. The rootfs stage only
# produces architecture-independent files. The image holds the binary, the CA
# bundle, the empty data and recovery directories and /tmp; no shell, no
# package manager, no /etc/passwd (the binary uses numeric IDs only).
#
# It replaces the Python image (Dockerfile at the repository root) without
# changes to existing installations: port 5000, the volumes /app/data and
# /app/recovery, the LDAP secret mount /run/webssh-auth, UID 1000 by default
# and 99:100 on Unraid, the same health check timing. /app/entrypoint.sh,
# python and /bin/sh are links to the binary that accept only the documented
# command forms of the Python image and its Compose files (ADR 0011,
# cmd/webssh/legacy.go, pyshim.go, healthshim.go).

FROM --platform=$BUILDPLATFORM golang:1.27.4@sha256:5f1b98fa02fe396ebce2a0227a0e08309e11792915b9dd2e1f71053d7e7e6666 AS build
WORKDIR /src
COPY go.mod go.sum ./
# The patched SMB client fork is bound by a replace directive in go.mod
# (third_party/README.md); the module download needs its go.mod.
COPY third_party/go-smb2 ./third_party/go-smb2
RUN --mount=type=cache,target=/go/pkg/mod go mod download && go mod verify
COPY cmd ./cmd
COPY internal ./internal
COPY static ./static
COPY scripts/stage-webassets.sh ./scripts/
ARG TARGETOS=linux
ARG TARGETARCH
ARG VERSION=3.4.0
ARG VCS_REF=unknown
# scripts/stage-webassets.sh copies the frontend assets from static/ to
# internal/httpapi/webassets (a build output, ignored by Git and by the build
# context) without the authoring sources; the binary embeds that directory.
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    sh scripts/stage-webassets.sh \
    && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false \
       -ldflags "-s -w -X github.com/bifrost0x/webssh/internal/buildinfo.version=${VERSION} -X github.com/bifrost0x/webssh/internal/buildinfo.revision=${VCS_REF}" \
       -o /out/webssh ./cmd/webssh

FROM --platform=$BUILDPLATFORM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS rootfs
# CI changes this value per run so the CA bundle cannot come from a stale
# layer; Trivy does not see the bundle in a scratch image.
ARG OS_PACKAGE_REFRESH=local
# Docker seeds an empty named volume from the image and gives it the owner of
# the image directory. The placeholder keeps the recovery volume non-empty
# after the first copy, so a custom-UID volume keeps its ownership when the
# container is recreated (as in the Python image).
RUN apk upgrade --no-cache ca-certificates-bundle \
    && mkdir -p /rootfs/etc/ssl/certs /rootfs/app/data/logs /rootfs/app/data/keys /rootfs/app/recovery /rootfs/tmp \
       /rootfs/run/webssh-auth /rootfs/bin /rootfs/usr/local/bin \
    && cp /etc/ssl/certs/ca-certificates.crt /rootfs/etc/ssl/certs/ca-certificates.crt \
    && chmod 0644 /rootfs/etc/ssl/certs/ca-certificates.crt \
    && chmod 1777 /rootfs/tmp \
    && chmod 0700 /rootfs/app/data /rootfs/app/data/logs /rootfs/app/data/keys /rootfs/app/recovery /rootfs/run/webssh-auth \
    && install -m 600 /dev/null /rootfs/app/recovery/.webssh-volume \
    && chown -R 1000:1000 /rootfs/app/data /rootfs/app/recovery /rootfs/run/webssh-auth \
    && ln -s webssh /rootfs/app/entrypoint.sh \
    && ln -s /app/webssh /rootfs/usr/local/bin/python \
    && ln -s /app/webssh /rootfs/usr/local/bin/python3 \
    && ln -s /app/webssh /rootfs/bin/sh

# Trivy does not detect BusyBox; tests/image/check.sh asserts its version.
FROM busybox:1.38-musl@sha256:80e38f9a1b39188b8bdb28879178edb322a4402b081a9aedda1924609decd6f6 AS busybox

FROM scratch AS runtime
ARG VERSION=3.4.0
ARG VCS_REF=unknown
LABEL org.opencontainers.image.source=https://github.com/bifrost0x/webssh \
      org.opencontainers.image.description="Self-hosted SSH, SFTP and SMB in the browser" \
      org.opencontainers.image.licenses=Apache-2.0 \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.revision=$VCS_REF
COPY --from=rootfs /rootfs/ /
COPY LICENSE NOTICE THIRD-PARTY-NOTICES /app/
# Root-owned and not writable by the service, so a compromised process
# cannot change the code that later starts or runs health checks.
COPY --from=build --chmod=0555 /out/webssh /app/webssh
# PATH as in the Python image, so "python" in exec-form health checks of
# existing Compose files resolves to the link above.
ENV PATH=/usr/local/bin:/usr/bin:/bin \
    HOST=0.0.0.0 \
    PORT=5000 \
    DATA_DIR=/app/data
WORKDIR /app
VOLUME /app/data
USER 1000:1000
EXPOSE 5000
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/app/webssh", "healthcheck"]
ENTRYPOINT ["/app/webssh"]
# The container port stays 5000 whatever HOST and PORT say, as with the
# Gunicorn command of the Python image.
CMD ["serve", "--bind", "0.0.0.0:5000"]

# Diagnostic variant (tags debug and <version>-debug): the same image plus a
# static BusyBox, whose sh replaces the /bin/sh link.
FROM runtime AS debug
COPY --from=busybox /bin/ /bin/

# Default target: no shell; diagnostics through webssh subcommands.
FROM runtime AS release
