# Installation from Source

WebSSH is a single Go program. Building it from source gives the same
binary the container runs, for operators who do not use containers and for
development. The supported source platform is Linux on `amd64` or `arm64`.
The container image remains the simplest deployment: it supplies a
non-root runtime, the persisted secret and a health check.

## Requirements

- Linux on `amd64` or `arm64`.
- Go at the version named by the `go` line in `go.mod`. With an older Go
  installed, `go` downloads the required toolchain itself unless
  `GOTOOLCHAIN=local` is set.
- Git.
- No C compiler: the build uses `CGO_ENABLED=0`.
- Node.js only when updating or testing frontend assets. It is not needed
  to build or run WebSSH.

## Build

```bash
git clone https://github.com/bifrost0x/webssh.git
cd webssh
scripts/stage-webassets.sh
CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w -X github.com/bifrost0x/webssh/internal/buildinfo.version=$(git describe --tags --always | sed 's/^v//') -X github.com/bifrost0x/webssh/internal/buildinfo.revision=$(git rev-parse HEAD)" \
  -o webssh ./cmd/webssh
./webssh version
```

`scripts/stage-webassets.sh` copies `static/` into
`internal/httpapi/webassets/`, which the binary embeds. Run it again after
every change below `static/`. Without the `-ldflags` values the binary
reports the version `dev`.

To build for the other architecture, set `GOARCH=arm64` or
`GOARCH=amd64`; the result runs on any Linux of that architecture.

## Development start

```bash
export DEBUG=True
export DATA_DIR="$PWD/data"
./webssh serve
```

Open `http://127.0.0.1:5000`. With `DEBUG=True` WebSSH uses a temporary
`SECRET_KEY` when none is configured, so sign-ins and sealed data do not
survive a restart; never use it outside development.

`go run -tags devfs ./cmd/webssh serve` reads `static/` directly instead of
the embedded copy, so frontend changes show after a page reload.

## Production start without a container

Outside the container the defaults are the same as inside it, apart from
the listen address:

- `serve` listens on `HOST` and `PORT`, by default `127.0.0.1:5000`.
  `--bind host:port` overrides both. The image passes `--bind 0.0.0.0:5000`.
- `DATA_DIR` defaults to `/app/data`. Set an absolute directory owned by the
  service account.

```bash
export DATA_DIR=/var/lib/webssh
export DEPLOYMENT_PROFILE=production
export WEBSSH_ORIGIN=https://ssh.example.com
export CORS_ORIGINS=https://ssh.example.com
export SESSION_COOKIE_SECURE=true
export REGISTRATION_ENABLED=False
export BOOTSTRAP_REGISTRATION_ENABLED=false
export BLOCK_INTERNAL_SSH=true
export TRUSTED_PROXIES=1
export TRUSTED_PROXY_CIDRS=127.0.0.1/32

./webssh serve --bind 127.0.0.1:5000
```

Run exactly one server per `DATA_DIR`; a second one refuses to start
because of the lock in `DATA_DIR/go/webssh.lock`. Terminate TLS at a
trusted reverse proxy; the bind address, `TRUSTED_PROXIES` and
`TRUSTED_PROXY_CIDRS` must match the real network boundary. Keep the
process under a supervisor that restarts it, and stop it with SIGTERM: the
server stops accepting work, reports not ready and finishes within
`RUNTIME_SHUTDOWN_GRACE_SECONDS` (5 by default, at most 30); a second signal
ends it at once.

The first administrator comes from the command line:

```bash
./webssh create-admin --username admin
```

All other commands are listed by `./webssh help` and in the
[operations guide](https://github.com/bifrost0x/webssh/blob/main/docs/operations-guide.md).

## Persistent data

`DATA_DIR` holds the database (`go/webssh.db`), the key material, the
generated `secret_key`, host trust, logs and temporary working
directories. WebSSH creates `DATA_DIR`, `logs/` and `keys/` with mode
`0700` and the database and key files with `0600`; it refuses to start when
key files are readable by others. Back it up with `webssh backup create` or
as a whole directory while the server is stopped. See
[Data Storage and Persistence](Data-Storage-and-Persistence).

## Upgrading a 3.3 source installation

A 3.3 source installation ran `start.py` or Gunicorn on a Python
environment. Point the Go binary at the same `DATA_DIR` and the same
`SECRET_KEY`; the first start migrates the data as described in
[Upgrading to 3.4](Upgrading-to-3.4). The Python virtual environment is
not needed afterwards.

## Frontend assets

WebSSH has no frontend build pipeline. Browser dependencies are pinned in
`package.json`, copied to `static/vendor/`, committed and served locally. To
refresh them intentionally:

```bash
npm install
npm run vendor
npm run vendor:check
```

Do not add runtime CDN dependencies; the CSP and the vendor integrity
checks assume local assets.

## Continue

- [Configuration Reference](Configuration-Reference)
- [Development and Testing](Development-and-Testing)
- [Production Deployment](Production-Deployment)
