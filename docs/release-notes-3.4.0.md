# WebSSH 3.4.0

WebSSH 3.4 replaces the Python server with a new server written in Go. The
web interface, your data and the way you deploy WebSSH stay the same. On its
first start 3.4 copies the 3.3 data into its own database, checks every
copied record and leaves the 3.3 data untouched, so the way back to 3.3
stays open until you remove the old data yourself.

Read [Upgrading to 3.4](wiki/Upgrading-to-3.4.md) before you update. It lists
every change you can notice (`U01` and following), the way back to 3.3 and
how to remove the 3.3 data later.

## Highlights

- **New server, same product.** SSH terminals, SFTP and SMB file workspaces,
  transfers, saved hosts, jump hosts, SOCKS5 proxies, saved passwords,
  commands, runbooks and schedules, the Overview board, Herdr, Tailscale SSH
  and the SSH gateway work as in 3.3. Accounts, passwords, TOTP, recovery
  codes and passkeys carry over; identity providers need no change.
- **Automatic, verified migration.** The first start migrates every kind of
  3.3 data, verifies it before it activates the result and writes a report to
  `DATA_DIR/go/migration-report-<UTC>.json`. If it cannot copy everything, it
  stops without writing and names the cause (`U08` to `U14`).
  `webssh migrate --dry-run` previews the migration without changing
  anything.
- **Way back to 3.3.** The 3.3 image on the unchanged volume starts as
  before. `webssh migrate --replace` migrates again after a way back.
  `webssh legacy purge` removes the 3.3 data only after a verified backup.
- **Smaller, harder image.** The image is built `FROM scratch`: the binary,
  the CA bundle and the license files, no shell, no Python and no OS
  packages. Port 5000, the volumes `/app/data` and `/app/recovery`, UID/GID
  1000 (Unraid 99:100) and the health check timing stay the same. A `:debug`
  image adds a BusyBox shell for troubleshooting (`U15`).
- **One live connection.** The browser uses a single WebSocket at
  `<APPLICATION_ROOT>/ws` instead of Socket.IO; long polling is gone
  (`U29`). Reverse proxies must forward WebSocket upgrades and the `Origin`
  header for that path.
- **Overview host cards.** The cards of a row line up with their status and
  actions at the bottom, and the host details open as a popover instead of
  unfolding inside the card (`U100`).
- **Command line.** `webssh <command>` replaces `flask --app start:app`.
  The 3.3 command forms and health checks of the shipped Compose files keep
  working until the next major release (`U16`, `U18`).

## Security

- A session ends on every live channel at once when it is revoked: sign-out,
  password or factor change, lock, deletion and role change close terminals
  and file sources of the account without a grace period. Lowering
  an administrator's role ends the admin rights immediately.
- Authentication and the access level are checked before a request body is
  read, and request bodies share a global budget with a per-account share,
  so slow uploads of one account cannot block others (`U96`).
- Turning on the tailnet block closes open connections that the block now
  refuses, as 3.3 did.
- Forwarded headers count only from the networks in the new
  `TRUSTED_PROXY_CIDRS` (`U24`). Requests from other sites are refused with
  403 (`U33`).
- Saved passwords are only sent over HTTPS and only to the target the page
  confirmed, also on jump-host, SOCKS5 and gateway paths.
- Secrets in the new database are sealed with a keyring derived from
  `SECRET_KEY` and `logs/.webssh-go/keyring-material` (`U06`). Keep both in
  volume backups.
- Restoring a backup with a different `SECRET_KEY` while 3.3 data exists
  re-seals the backup's secrets under the active key instead of replacing
  `DATA_DIR/secret_key`, so the way back to 3.3 keeps working.

## Upgrade and recovery

1. Make a backup in 3.3 and copy it off the host; better, also copy the
   stopped data volume.
2. Note where `SECRET_KEY` comes from. With an environment variable, 3.4
   needs the same value (`U10`).
3. Stop and remove the 3.3 container. Never run 3.3 and 3.4 on the same
   volume at the same time (`U05`).
4. Remove Compose overrides that start `sh`, `gunicorn` or `python`
   (`U15`, `U16`).
5. Start 3.4 and watch the log for `migration completed`. Everyone signs in
   once (`U04`).

Behaviour changes to check before upgrading, in short; the full list with
what to do is in [Upgrading to 3.4](wiki/Upgrading-to-3.4.md#changes-you-can-notice):

- `docker compose exec webssh sh` no longer opens a shell; use
  `/app/webssh <command>` or the `:debug` image.
- Socket.IO and long polling are gone; proxy rules must cover `/ws`.
- `TZ` must be an IANA zone name (`U20`).
- Redis rate limiting is no longer supported; `RATELIMIT_STORAGE_URL`,
  `GUNICORN_THREADS` and `BACKGROUND_WORKERS` are ignored with a warning
  (`U25`).
- Backups are tar archives; 3.4 backups cannot be restored with 3.3 (`U77`).
- RSA keys below 1024 bits, DSA keys and the algorithms aes192-cbc,
  aes256-cbc and hmac-md5 are not supported; the migration report names
  affected keys (`U45`). Other legacy algorithms stay behind the legacy
  setting (`U44`).
- DATA_DIR on a tmpfs counts against the container's memory limit during the
  first start (`U14`).
- Server management now lists the first systemd service and the first Docker
  container of a host, which 3.3 left out (`U99`).

Only Linux is supported: the image for `linux/amd64` and `linux/arm64` and a
source build on Linux. Windows and macOS binaries and the systemd service of
earlier releases are gone.

See [Upgrading to 3.4](wiki/Upgrading-to-3.4.md) and
[Upgrading, Rollback, and FAQ](wiki/Upgrading-Rollback-and-FAQ.md).

[Changes from 3.3.0](https://github.com/bifrost0x/webssh/compare/v3.3.0...v3.4.0)

## Known risks of this release

Tested in an isolated lab, not against every real deployment:

- **Tailscale SSH** was tested against a stand-in for tailscaled with real
  kernel routing in a network namespace, not against a real tailnet.
- **SSH gateway** was tested against a Warpgate container in the lab, not
  against production gateway setups.
- **Herdr** was tested against Herdr 0.9.5 on an SSH host in a lab
  container, not against real hosts with other Herdr versions or agents,
  and the browser flow of the Herdr session mode against the new server
  only through the end-to-end stand-ins.
- **Unraid** was checked with the template and the 99:100 runtime user in
  containers, not on Unraid hardware.
- **ARM64**: the image was cross-compiled and checked only under QEMU
  emulation, not on ARM64 hardware.

The migration was verified against generated data sets, real 3.x data
directories and backups. Validate your own configuration on a copy of the
data volume first, and keep the 3.3 backup until 3.4 has run for a while.

## Verified delivery

To be filled in from the tag CI run: tag commit, image digests for AMD64 and
ARM64, vulnerability gate, runtime checks and SBOM.
