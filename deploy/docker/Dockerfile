# syntax=docker/dockerfile:1
#
# WebSSH (Go) on scratch. Build from the repository root:
#
#   docker build -f deploy/docker/Dockerfile --target release -t webssh-go:m1 .
#   docker build -f deploy/docker/Dockerfile --target debug -t webssh-go:m1-debug .
#
# deploy/docker/Dockerfile.dockerignore limits the context to the Go module
# and the frontend assets. The binary is cross-compiled on the build platform
# (CGO_ENABLED=0), so an arm64 image needs no emulation. The rootfs stage only
# produces architecture-independent files. The image holds the binary, the CA
# bundle, the empty data and recovery directories and /tmp; no shell, no
# package manager, no /etc/passwd (the binary uses numeric IDs only).
#
# The Python image (Dockerfile at the repository root) is unaffected.

FROM --platform=$BUILDPLATFORM golang:1.27.4@sha256:5f1b98fa02fe396ebce2a0227a0e08309e11792915b9dd2e1f71053d7e7e6666 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download && go mod verify
COPY cmd ./cmd
COPY internal ./internal
COPY static ./static
ARG TARGETOS=linux
ARG TARGETARCH
ARG VERSION=3.4.0-m1
ARG VCS_REF=unknown
# The frontend assets are copied from static/ to internal/httpapi/webassets
# (a build output, ignored by Git and by the build context), the same step as
# scripts/stage-webassets.sh. The binary embeds that directory.
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    mkdir -p internal/httpapi/webassets \
    && cp -a static/. internal/httpapi/webassets/ \
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
    && cp /etc/ssl/certs/ca-certificates.crt /rootfs/etc/ssl/certs/ca-certificates.crt \
    && chmod 0644 /rootfs/etc/ssl/certs/ca-certificates.crt \
    && chmod 1777 /rootfs/tmp \
    && chmod 0700 /rootfs/app/data /rootfs/app/data/logs /rootfs/app/data/keys /rootfs/app/recovery \
    && install -m 600 /dev/null /rootfs/app/recovery/.webssh-volume \
    && chown -R 1000:1000 /rootfs/app/data /rootfs/app/recovery \
    && ln -s webssh /rootfs/app/entrypoint.sh \
    && mkdir -p /rootfs/usr/local/bin \
    && ln -s /app/webssh /rootfs/usr/local/bin/python

FROM busybox:1.37-musl@sha256:f6a95d611e0a8780fabdb2aec43e31275b2720dfefa3e41b16835bfc42454478 AS busybox

FROM scratch AS runtime
ARG VERSION=3.4.0-m1
ARG VCS_REF=unknown
LABEL org.opencontainers.image.source=https://github.com/bifrost0x/webssh \
      org.opencontainers.image.description="WebSSH Go server, preview build: sign-in, hosts and SSH terminal in the browser" \
      org.opencontainers.image.licenses=Apache-2.0 \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.revision=$VCS_REF
COPY --from=rootfs /rootfs/ /
# Root-owned and not writable by the service, so a compromised process
# cannot change the code that later starts or runs health checks.
COPY --from=build --chmod=0555 /out/webssh /app/webssh
ENV HOST=0.0.0.0 \
    PORT=5000 \
    DATA_DIR=/app/data
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

# Diagnostic variant (tag :m1-debug): the same image plus a static BusyBox.
FROM runtime AS debug
COPY --from=busybox /bin/ /bin/

# Default target: no shell; diagnostics through webssh subcommands.
FROM runtime AS release
