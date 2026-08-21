# Installation from Source

Source installation is useful for development, debugging, and operators who do
not use containers. Docker remains the simplest supported deployment because
the image supplies a non-root runtime, persistent-secret bootstrap, Gunicorn,
and a healthcheck.

## Requirements

- Python 3.11 or newer.
- Git.
- An operating-system build environment capable of installing the locked
  binary dependencies for the selected Python version.
- Node.js only when updating or testing frontend assets. Node is not required
  to serve WebSSH at runtime.

## Clone and create a virtual environment

Linux or macOS:

```bash
git clone https://github.com/bifrost0x/webssh.git
cd webssh
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
python -m pip install --require-hashes -r requirements.txt
```

PowerShell:

```powershell
git clone https://github.com/bifrost0x/webssh.git
Set-Location webssh
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install --require-hashes -r requirements.txt
```

The committed `requirements.txt` is a complete cross-platform lock with hashes.
Do not replace the hashed installation with an unconstrained `pip install`
workflow for production.

## Development start

Generate a strong development secret and run the app:

```bash
export SECRET_KEY=$(openssl rand -hex 32)
export DEBUG=True
python start.py
```

PowerShell:

```powershell
$env:SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
$env:DEBUG = 'True'
python start.py
```

Open `http://127.0.0.1:5000`.

## Non-container production start

Outside the container, production must receive an explicit `SECRET_KEY`.
Configure the production profile and run exactly one Gunicorn `gthread` worker:

```bash
export SECRET_KEY=$(openssl rand -hex 32)
export DEPLOYMENT_PROFILE=production
export CORS_ORIGINS=https://ssh.example.com
export SESSION_COOKIE_SECURE=true
export REGISTRATION_ENABLED=False
export BOOTSTRAP_REGISTRATION_ENABLED=false
export BLOCK_INTERNAL_SSH=true
export TRUSTED_PROXIES=1

gunicorn \
  --worker-class gthread \
  --workers 1 \
  --threads 64 \
  --bind 127.0.0.1:5000 \
  start:app
```

Place a service manager around Gunicorn and terminate TLS at a trusted reverse
proxy. The bind address and `TRUSTED_PROXIES` value must match the real network
boundary.

## Persistent data

`DATA_DIR` defaults to `./data` for a source checkout. It contains the database,
per-user JSON stores, encrypted keys, host trust, logs, and temporary working
directories. Set an absolute service-owned directory for a managed deployment:

```bash
export DATA_DIR=/var/lib/webssh
```

Back up this directory with WebSSH's native backup tooling rather than copying
live files independently. See [Data Storage and Persistence](Data-Storage-and-Persistence).

## Frontend assets

WebSSH has no frontend build pipeline for normal runtime. Browser dependencies
are pinned in `package.json`, copied to `static/vendor/`, committed, and served
locally. To intentionally refresh them:

```bash
npm install
npm run vendor
npm run vendor:check
```

Do not add runtime CDN dependencies; the offline-capable CSP and vendor
integrity checks assume local assets.

## Updating dependencies

Direct Python constraints live in `requirements.in` and
`requirements-test.in`. Regenerate the hashed locks with:

```powershell
pwsh -File scripts/lock_requirements.ps1
```

Verify reproducibility without changing them:

```powershell
pwsh -File scripts/lock_requirements.ps1 -Check
```

## Continue

- [Configuration Reference](Configuration-Reference)
- [Development and Testing](Development-and-Testing)
- [Production Deployment](Production-Deployment)
