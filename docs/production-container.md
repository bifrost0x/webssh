# Production container boundaries

Use Docker Compose 2.24.4 or newer and set `WEBSSH_ORIGIN` to the exact public
HTTPS origin before starting the base file with `docker-compose.production.yml`.
The production overlay retains the established HTTPS, cookie, registration,
proxy and target-policy settings and binds port 5000 to loopback.

```bash
export WEBSSH_ORIGIN=https://ssh.example.com
docker compose -f docker-compose.yml -f docker-compose.production.yml config
docker compose -f docker-compose.yml -f docker-compose.production.yml up -d
```

Updating this configuration does not impose new filesystem, task or memory
limits, replace a custom runtime directory, or add temporary mounts. Existing
custom limits and mounts remain operator-controlled. Updating an image alone
does not change Compose settings. Use files from the same release or commit.

## Optional container restrictions

Append `docker-compose.hardened.yml` after the production overlay to enable a
read-only root filesystem, dropped Linux capabilities, `no-new-privileges`,
bounded tmpfs mounts and explicit memory/task ceilings:

```bash
docker compose -f docker-compose.yml -f docker-compose.production.yml -f docker-compose.hardened.yml config
docker compose -f docker-compose.yml -f docker-compose.production.yml -f docker-compose.hardened.yml up -d
```

This is an explicit deployment choice. Check application/custom entrypoint
writes, custom mounts, runtime ownership and workload capacity before enabling
it. It is intended for the current image; test older or derived images before
applying these restrictions. Existing installations can use the current image
with their established deployment settings without enabling this overlay.

The standard image runs as UID/GID 1000. With hardening enabled, writable
locations are:

| Path | Purpose | Lifetime |
| --- | --- | --- |
| `/app/data` | Database, generated secret, user files and application temporary files | Persistent data volume |
| `/app/recovery` | Backup operations, restore staging and rollback copies in a private per-instance directory | Persistent recovery volume |
| `/tmp` | General temporary files | tmpfs, cleared on container recreation |
| `/run/webssh` | Private Gunicorn runtime/control socket directory | 1 MiB tmpfs, mode 0700 |

Both tmpfs mounts disable execution, device nodes and set-user-ID behavior.
`XDG_RUNTIME_DIR=/run/webssh` keeps Gunicorn runtime files off the read-only root.
Keep the data and recovery volumes writable by the effective container user.
For a custom `user:` setting, set `WEBSSH_RUNTIME_UID` and `WEBSSH_RUNTIME_GID`
to the same numeric IDs and provision matching permissions on the persistent
mounts. These variables set runtime-mount ownership; they do not change the
container user or recursively change existing data permissions.

| Compose variable | Hardened default | Purpose |
| --- | --- | --- |
| `WEBSSH_PIDS_LIMIT` | `512` | Maximum tasks, including processes and threads |
| `WEBSSH_MEMORY_LIMIT` | `2g` | Container memory ceiling, including tmpfs usage |
| `WEBSSH_TMPFS_SIZE` | `128m` | `/tmp` capacity shared by temporary operations |
| `WEBSSH_RUNTIME_UID` / `WEBSSH_RUNTIME_GID` | `1000` / `1000` | Private runtime-mount owner |

Set these in the Compose environment or `.env`, inspect `docker compose config`
with the complete file list, then recreate the service. For example,
`WEBSSH_TMPFS_SIZE=1g` expands `/tmp`; provision a suitable memory limit too.
A custom `TRANSFER_TEMP_DIR` under `/tmp` shares that capacity. Concurrent
archive/export operations can exhaust it even when each is below the application
quota. For larger workloads, put transfer scratch files on a sufficiently sized
writable mount or retain the default `DATA_DIR/tmp`. Normal HTTP uploads stream
to their destination and do not require their full size in `/tmp`.
Custom write paths outside the documented volumes need their own writable
mount when root is read-only. Do not put durable recovery on tmpfs.

Keep exactly one Gunicorn worker; the defaults of 64 Gunicorn threads and 48
socket connections leave HTTP capacity available. SSH transport threads,
background work, transfers and tmpfs contents also consume resources. Monitor
memory/OOM events and task counts before raising application concurrency.
Resource ceilings are not a load-tested concurrency guarantee. The 40-second
stop grace period allows bounded application shutdown to finish.

## Backup and restore compatibility

Recovery storage must be outside the data directory, static files and logs;
a restore also rejects recovery storage overlapping its actual destination.
Provision space for the archive, extracted files and rollback copies. Restore
writes use atomic file copies, so recovery can reside on a separate filesystem.

`flask --app start:app backup create --confirm-offline` still uses the parent
of `DATA_DIR` when writable. If that directory is read-only or denies writes,
the command uses the private per-instance directory under `BACKUP_TEMP_DIR`
and prints the archive's actual path. An explicit `--destination` is never
redirected; insufficient space, source-read errors and existing destinations
still fail. With the supplied Compose files, fallback archives reside on the
persistent recovery volume. With custom settings, use durable backup storage
and copy completed archives to encrypted off-host storage. A backup left in a
one-off container's writable layer or temporary directory is not durable.
CLI backup and restore require a stopped application and the offline acknowledgement.

Restore rejects database triggers, views and virtual tables, which WebSSH does
not create, before replacing existing data. The same check protects internal
recovery snapshots and authentication-state cleanup. Archives containing SQLite
WAL, shared-memory or journal sidecars are rejected rather than replayed after
validation. Backup creation consolidates committed WAL data into the database
snapshot; it does not silently discard those changes. For an older archive with
sidecars, create a new consistent backup from the original stopped installation.
These checks reduce the import attack surface but do not replace SQLite security
updates or make untrusted database files safe to parse.

## Optional authentication and networking

For LDAP, merge base, LDAP and production files in this order, then append the
hardened file if wanted:

```bash
docker compose -f docker-compose.yml -f docker-compose.ldap.yml -f docker-compose.production.yml config
docker compose -f docker-compose.yml -f docker-compose.ldap.yml -f docker-compose.production.yml up -d
```

Configure LDAP and initialize secrets using [the LDAP guide](ldap-authentication.md)
first. `/run/webssh-auth` remains a separate read-only secret-volume mount; it is
not covered by `/run/webssh`. Only the explicitly invoked `ldap-tools` helper
writes those secrets. The optional limits apply to the WebSSH service.

The overlays do not create a Tailscale interface or daemon.
[Tailscale SSH](tailscale-ssh.md) needs its documented kernel interface and shared
network namespace plus explicit user, target and remote-user allowlists. Keep
TUN devices and networking capabilities in the separate Tailscale service.
A custom sidecar deployment must move published ports to the namespace-owning
sidecar. Production target policy and interface checks still apply.

## Disposable runtime verification

`scripts/check_hardened_container.py --image IMAGE --revision COMMIT_SHA
--platform linux/amd64` exercises the established production setup, optional
hardening, and hardening with a custom UID/GID, transfer path and larger tmpfs. It checks
revision, readiness, filesystem/process restrictions, a 160 MiB scratch write,
online backup, offline CLI backup, restore, SQLite integrity, restart and graceful
shutdown. Use `linux/arm64` for the other release platform. `--profile` can select
`compatible`, `hardened` or `hardened-custom`; CI/release checks run all three.
The helper uses anonymous volumes and uniquely labelled disposable containers,
and checks ownership before removing them. It does not use deployment data.
Image scanning and immutable release-candidate checks remain required. These
are functional smoke tests, not proof for every custom image or workload.
