# Container image and release binaries

## Image

The `Dockerfile` at the repository root builds the image; `.dockerignore`
limits the build context to the Go module and the frontend assets. The image
of 3.4 replaced the 3.3 image without changes to existing installations:

| | |
|---|---|
| Port | 5000 |
| Volumes | `/app/data`, `/app/recovery`; LDAP secrets under `/run/webssh-auth` |
| User | 1000:1000; Unraid runs it as 99:100 (`unraid/webssh.xml`) |
| Health check | `/app/webssh healthcheck` (exec form, 30 s / 5 s / 10 s / 3 retries) |
| 3.3 command forms | `/app/entrypoint.sh flask --app start:app <command>`, `python /app/deployment/ldap_secret_cli.py <command>` and the `python`/`CMD-SHELL` health checks of the 3.3 and earlier `docker-compose.yml` files keep working through links to the binary; anything else is refused |

The image is `scratch` with the binary, the CA bundle, the license files and
the empty data directories; there is no shell. Two targets:

| Target | Tags | Content |
|---|---|---|
| `release` (default) | `<version>`, `<major>.<minor>`, `latest` | as above |
| `debug` | `debug`, `<version>-debug` | the same image plus a static BusyBox, for inspecting volumes and the file system |

```sh
docker build --build-arg VERSION=3.4.0 --build-arg VCS_REF="$(git rev-parse HEAD)" \
  -t webssh:local .
docker build --target debug \
  --build-arg VERSION=3.4.0 --build-arg VCS_REF="$(git rev-parse HEAD)" -t webssh:local-debug .
```

`tests/image/check.sh` builds both targets and checks them, including the
unchanged Compose files of the 3.3 release and the Unraid user;
`TRIVY=1` adds the Trivy scan.

## Rebuild rhythm

The image contains three parts that age without a code change: the Go
standard library in the binary, the CA bundle in
`/etc/ssl/certs/ca-certificates.crt` (from Alpine's `ca-certificates-bundle`,
refreshed on every CI build through `OS_PACKAGE_REFRESH`) and the fallback
roots of `golang.org/x/crypto/x509roots/fallback`, which only apply when the
bundle is missing.

- **Every release** is built with the newest Go patch release, a freshly
  pulled CA bundle and the newest `x509roots/fallback` pseudo-version.
  Dependabot proposes the base images of the `Dockerfile`
  (`golang`, `alpine`, `busybox`) and the tagged Go modules weekly
  (`.github/dependabot.yml`). `x509roots/fallback` has no tagged
  releases, and Dependabot is not relied on to move a pseudo-version, so
  the release commit updates the fallback roots by hand:

  ```sh
  go get golang.org/x/crypto/x509roots/fallback@latest && go mod tidy
  ```
- **Go security release or a govulncheck/Trivy finding** in a shipped
  component: a patch release within 7 days, for critical findings as soon
  as possible.
- **CA bundle**: at the latest every 3 months a patch release, even without
  other changes, and earlier when Mozilla distrusts a root that the bundle
  still carries.
- The weekly security workflow (`.github/workflows/security.yml`) builds the
  image from `main` and scans it with Trivy; a finding starts the patch
  release above.

Republishing an existing version tag with a different digest is not done;
every rebuild is a new patch version.

`deploy/docker/compose.m1.yml`, `compose.m1.tls.yml` and `Caddyfile.m1`
run a 3.4 trial on a copy of an existing data volume next to a running 3.3
instance; their comments describe the steps.

## Release binaries

Linux only (amd64, arm64); Windows and macOS have no release binaries.

```sh
scripts/build-release-binaries.sh 3.4.0
```

builds from a clean checkout into `dist/`: one reproducible
`webssh-<version>-linux-<arch>.tar.gz` per architecture with the binary,
`LICENSE`, `NOTICE` and `THIRD-PARTY-NOTICES`, and `SHA256SUMS`. The binary
reports `<version> (<commit>)` with `webssh version`.
