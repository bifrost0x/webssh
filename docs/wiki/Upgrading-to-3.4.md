# Upgrading to 3.4

WebSSH 3.4 replaces the Python server with a new server written in Go. The
web interface, the data you created and the way you deploy WebSSH stay the
same; the server underneath is new. This page lists what happens during the
update, every change you can notice, the way back to 3.3 and how to remove
the old data once you no longer need it.

Supported platforms are the container image for `linux/amd64` and
`linux/arm64` (Docker, Docker Compose, Unraid) and a source build on Linux.

The numbers in the first column (`U15` and so on) identify each entry, so an
issue or a question can point to one line.

## What stays the same

- Image name, container port 5000, the volumes `/app/data` and
  `/app/recovery`, the runtime user 1000:1000 (Unraid: 99:100).
- `DATA_DIR`, `SECRET_KEY` and the documented environment variables. Values
  are read the way 3.3 read them.
- Accounts, passwords, TOTP, recovery codes and passkeys. The WebAuthn
  relying party, the OIDC callback `/oidc/callback` and the GitHub callback
  `/auth/github/callback` are unchanged, so identity providers need no
  change.
- Hosts, jump hosts, SOCKS5 proxies, SSH keys, host keys, notes, commands,
  command sets, runbooks, schedules, saved passwords, SMB shares, settings
  and persistent tmux session names.
- Browser-local data (layouts, preferences kept in the browser) keeps its
  storage namespace.
- Backups made with 3.x restore on 3.4.
- The command form `/app/entrypoint.sh flask --app start:app <command>`
  keeps working until the next major release (see `U18`).
- The audit log `logs/security_audit.log` keeps its line format.
- Automation steps run in the remote login shell as before; with sudo they
  run as `sudo -n -- sh -c '<step>'`.
- Host names with non-ASCII characters are converted with IDNA 2003 as
  before, in saved hosts and in the allowlists of SOCKS5, SMB and Tailscale
  SSH.
- The LDAP filter syntax, `LDAP_CA_FILE` and the `ldap-tools` helper volume.

## Before you upgrade

1. Read this page to the end, in particular the [way back](#way-back-to-33).
2. Create a backup in 3.3 (**Settings Center → Backup & Restore**) and copy
   it off the host. Better still, also copy the whole data volume while
   WebSSH is stopped.
3. Note where `SECRET_KEY` comes from: the generated file
   `DATA_DIR/secret_key` (the default) or an environment variable. With an
   environment variable, 3.4 must receive the same value.
4. Stop and remove the 3.3 container. Never run 3.3 and 3.4 on the same
   data volume at the same time (`U05`).
5. Update the Compose file, or at least remove changes that need a shell or
   Python in the image: any `command:` or `entrypoint:` that starts
   `gunicorn`, `sh` or `python`, and health checks of your own that run
   other programs (`U15`, `U16`). The health checks of the 3.3 Compose
   files keep working.
6. Behind a reverse proxy, make sure it forwards WebSocket upgrades and the
   `Origin` header for every path below the WebSSH prefix (`U29`, `U30`).
7. Optional: preview the migration without changing anything:

   ```bash
   docker compose run --rm webssh migrate --dry-run
   ```

   The command prints the migration report as JSON. It activates nothing
   and leaves the 3.3 data untouched.

## What happens at the first start

| # | What happens | What to do |
|---|---|---|
| U01 | On its first start 3.4 finds the 3.3 data in `DATA_DIR`, copies everything into its own database in `DATA_DIR/go/` and checks every copied record before it activates the result. The start takes a few seconds longer than usual. | Nothing. Watch the log for `migration completed`. |
| U02 | The 3.3 data is only read, never changed or deleted. The exceptions are runtime paths: `logs/` and `keys/` get mode 0700, `keys/` is created when it is missing, and 3.4 appends its events to `logs/security_audit.log`. | Nothing. |
| U03 | The migration writes a report to `DATA_DIR/go/migration-report-<UTC>.json` (mode 0600), also when it fails. It lists what was migrated, records that were flagged and actions left to users or administrators: legacy SSH keys 3.4 cannot use (`U45`), schedules that need a new approval (`U73`), an old automation vault to import (`U70`). | Read the report and act on its `warnings` and `pending_user_actions`. |
| U04 | Everyone signs in once. Browser sessions, "remember me" cookies and known-device cookies are not carried over. Also discarded: enrollments in progress, step-up confirmations, issued first-factor bootstrap codes, sign-ins with OIDC or GitHub that were in progress, and the counters of the sign-in rate limits. Passwords, second factors and passkeys stay. | Tell users to expect one new sign-in. Issue new bootstrap codes where the report lists open ones. |
| U05 | If the 3.3 data changes while 3.4 runs, for example because a forgotten 3.3 container still uses the volume, 3.4 notices within a minute, reports not ready and refuses new sign-ins and changes until it is restarted. | Stop the 3.3 container, then see [Starting 3.4 again after the way back](#starting-34-again-after-the-way-back). |
| U06 | 3.4 creates `logs/.webssh-go/keyring-material` (32 random bytes). Together with `SECRET_KEY` it protects the secrets in the new database. While the 3.3 data exists the file lives below `logs/` on purpose, so that a backup made by 3.3 after a way back never carries it. | Do not delete `logs/.webssh-go/`. Keep it in volume backups. Without it, saved SSH keys, saved passwords and second factors cannot be read. |
| U07 | Settings whose default is safer in 3.4 keep their 3.3 behaviour on an upgraded installation. The migration records them explicitly: host discovery and reachability for all users (`U55`), legacy SSH algorithms (`U44`), the origin rule of `CORS_ORIGINS=*` (`U31`), the tailnet rule (`U51`) and the close confirmation of sessions. New installations get the safer defaults. | Review them in Administration once the update has settled. |

### When the first start stops

The migration stops without writing anything when it cannot copy the data
completely. 3.4 then exits, the 3.3 data is untouched and the message names
the way out:

| # | Message or code | Cause | Way out |
|---|---|---|---|
| U08 | `legacy_in_use` | 3.3 still runs on the volume, or its database or `operation.lock` is held. | Stop 3.3 and start 3.4 again. |
| U09 | `not_enough_space` | The volume needs room for about three times `app.db`, plus the user directories, plus 64 MiB. | Free space on the volume. |
| U10 | `secret_key_mismatch`, "SECRET_KEY does not match the stored data" | 3.3 received `SECRET_KEY` from the environment and 3.4 did not get the same value. | Pass the same `SECRET_KEY` to 3.4. |
| U11 | `python_restore_unfinished` | A 3.3 restore did not finish. | Start 3.3 once to finish or roll back the restore, stop it, then start 3.4. |
| U12 | for example `legacy_unsafe_path`, `legacy_unreadable`, `legacy_record_damaged` | A symbolic link, an unreadable or damaged file or an invalid record in the 3.3 data, for example a corrupt `app.db` or an SMB share record that contains a password, or a single stored secret that does not decrypt while `SECRET_KEY` decrypts the others (`legacy_record_damaged`). The message names the file, or the entity, account and record. | Fix or remove the named file in 3.3, then start 3.4 again. |
| U13 | `migration_incomplete_build` | The 3.4 build cannot migrate every kind of data it found. | Use a released 3.4 image. |
| U14 | "exceeds 67108864 bytes" | A single store file is larger than 64 MiB. The migration handles one account at a time, so its memory depends on the largest account's stores, not on the number of accounts: accounts with stores close to that limit need about 0.9 GB for a moment. 3.4 sets the Go memory limit to three quarters of the container's `mem_limit` unless `GOMEMLIMIT` is set. If `DATA_DIR` lies on a tmpfs, everything the migration writes there (the new database and its staging copy) also counts against the container's memory limit, and the first start can be killed for lack of memory. | Reduce the store in 3.3 (`connection-store`), or raise the container's memory limit for the first start. Keep `DATA_DIR` on a disk volume, not on a tmpfs. |

## Changes you can notice

The `Kind` column says whether a change fixes a 3.3 problem (`fix`), is new
(`new`), removes something (`removed`) or follows a maintainer decision
(`decided`).

### Image, deployment and command line

| # | Change | Kind | What to do |
|---|---|---|---|
| U15 | The image has no shell and no Python. `/bin/sh` and `python` exist only to run the health checks of the 3.3 Compose files (`U16`) and the LDAP helper (`U18`); a Compose `command:` or `entrypoint:` that starts anything else with `sh`, `gunicorn` or `python` exits with "the image has no shell". `docker compose exec webssh sh` no longer opens a shell. A `:debug` image with a BusyBox shell exists for troubleshooting. | decided | Use the commands of `/app/webssh` (`docker compose exec webssh /app/webssh help`). |
| U16 | The image's health check is `/app/webssh healthcheck`, with the 3.3 timing (30 s interval, 5 s timeout, 10 s start period, 3 retries). The `healthcheck` blocks of the 3.3 Compose files (`python -c …` and the `CMD-SHELL` loop) still work: 3.4 answers exactly these commands and checks the same port or `/ready` as before. Health checks that run other commands report `unhealthy`. | decided | Nothing for the shipped Compose files; switch your own health checks to `/app/webssh healthcheck`. |
| U17 | Unraid: the console of the container (**Console** in the Docker tab) has nothing to open, because the image has no shell. The 3.4 template drops the shell setting. | decided | Run commands with `docker exec webssh /app/webssh <command>` from the Unraid terminal. |
| U18 | The command line is `webssh <command>`: `serve`, `healthcheck`, `create-admin`, `reset-password`, `ldap-secret`, `issue-factor-bootstrap`, `connection-store`, `rotate-secret-key`, `migrate`, `legacy purge`, `backup create\|verify\|restore`, `version`. The 3.3 forms `/app/entrypoint.sh flask --app start:app <command>` and `python /app/deployment/ldap_secret_cli.py <command>` (the `ldap-tools` Compose profile) still work with the same options, exit codes and messages and print a notice with the new form. They are removed in the next major release. | decided | Switch scripts to `/app/webssh <command>`. |
| U19 | Admin commands (`create-admin`, `reset-password`, `issue-factor-bootstrap`) never migrate. On a 3.3 volume that 3.4 has not started on yet they stop with "has not been migrated yet". | new | Start 3.4 once first. |
| U20 | `TZ` must be an IANA name such as `Europe/Berlin`. POSIX rules such as `CET-1CEST,M3.5.0,M10.5.0/3` no longer work; an unknown value logs a warning and uses UTC. | decided | Use an IANA zone name. |
| U21 | A dangling symbolic link at `DATA_DIR/secret_key`, or a file in place of the `logs/` or `keys/` directory, stops the start. A permission error names the runtime user and the `chown` that fixes it. | fix | Fix the path as the message says. |
| U22 | The keyring material and the database in `go/` must be regular files with mode 0600. Group or other permissions, or a symbolic link inside `go/`, stop the start. | decided | `chmod 600` the named file; remove links. |
| U23 | Installation from source means building the Go binary on Linux ([Installation from Source](Installation-from-Source)). The Python development server (`start.py`) and its Windows and macOS use are gone. | decided | Use the container or build on Linux. |

### Configuration

| # | Change | Kind | What to do |
|---|---|---|---|
| U24 | New `TRUSTED_PROXY_CIDRS`: the networks or addresses of your reverse proxies. Forwarded headers count only when the direct peer is inside them, and every proxy in a chain must be listed. With `TRUSTED_PROXIES` above 0 and no CIDRs, 3.4 trusts every direct client as 3.3 did and warns at every start; with `DEPLOYMENT_PROFILE=production` the warning names `TRUSTED_PROXY_CIDRS` as a required setting, but the start is not refused. | new | Set `TRUSTED_PROXY_CIDRS` whenever `TRUSTED_PROXIES` is above 0. |
| U25 | Variables without meaning in 3.4 are accepted, ignored and named in a startup warning: `GUNICORN_THREADS`, `BACKGROUND_WORKERS`, `RATELIMIT_STORAGE_URL` (Redis is no longer supported; rate limits live in the process) and `PYTHON*` other than `PYTHON_DOTENV_DISABLED` (`U92`). Their values are still checked as in 3.3, so a way back still starts. `TRANSFER_TEMP_DIR` is no longer used; `BACKUP_RECOVERY_DURABLE` is read but no longer required (`U83`). | decided | Remove them from the Compose file when the way back is no longer needed; drop the Redis service. |
| U26 | Values that 3.3 parsed in a surprising way keep their 3.3 meaning and now log a warning, for example `yes` or `1` for a boolean (read as false), `" true"` with a space (false), or `" *"` in `CORS_ORIGINS` (not a wildcard). | fix | Read the startup warnings and correct the values. |
| U27 | `REQUESTS_CA_BUNDLE` and `CURL_CA_BUNDLE` add certificates to the system trust store instead of replacing it, and apply to OIDC and GitHub. LDAP trusts only `LDAP_CA_FILE`, as before. A missing or empty bundle is an error. | decided | Check that the bundle path exists. |
| U92 | A `.env` file next to the binary (`/app/.env` in the image, the checkout for a build from source) is read with the rules of python-dotenv: variables already set in the environment win, `PYTHON_DOTENV_DISABLED` turns it off. A file that is not UTF-8, holds a NUL byte, is larger than 4 MiB or whose `${…}` interpolations add up to more than 4 MiB stops the start. The image does not contain a `.env`. | keep | Nothing, unless you mount a `.env` into `/app`. |
| U28 | A second cookie `<SESSION_COOKIE_NAME>_binding` binds the CSRF token to the browser, and a known device gets `<SESSION_COOKIE_NAME>_device`. `REMEMBER_COOKIE_NAME` must not use either name; the start fails if it does. | new | Allow the cookies in cookie policies. |

### Reverse proxy and live connection

| # | Change | Kind | What to do |
|---|---|---|---|
| U29 | Socket.IO is gone. The browser uses one WebSocket at `<APPLICATION_ROOT>/ws` (subprotocol `webssh.v1`); there is no long polling. `/socket.io/` answers 410, which makes an old page ask for a reload. | removed | Proxy rules written for `/socket.io/` must cover `/ws`, with the upgrade headers. See [Reverse Proxy and Subfolder Deployment](Reverse-Proxy-and-Subfolder-Deployment). |
| U30 | A WebSocket upgrade without an `Origin` header is refused with 403. | decided | Configure the proxy to pass `Origin` through. |
| U31 | An explicit `CORS_ORIGINS` list always includes WebSSH's own address, and the scheme counts (`http://` and `https://` differ). An upgraded installation with `CORS_ORIGINS=*` keeps the 3.3 rule, which ignored the scheme, and logs a warning. | fix | List the exact origins, including the scheme. |
| U32 | A refused live connection (`MAX_SOCKET_CONNECTIONS`, `MAX_SOCKET_CONNECTIONS_PER_USER`, defaults 48 and 8 as before) is closed with a message that names the limit, instead of a generic connection error. | fix | Close tabs or raise the limits. |
| U33 | A request that changes data and comes from another site is refused with 403 `forbidden` (3.3: 400 `csrf_expired`). Browsers older than 2023 behind a proxy that rewrites the host need `TRUSTED_PROXIES`. | fix | Set `TRUSTED_PROXIES` and `TRUSTED_PROXY_CIDRS` behind such proxies. |
| U94 | WebSSH holds at most 4096 HTTP connections at once, live connections included; further connections wait until one closes. There is no setting; 3.3 under Gunicorn held at most 1000. | new | Nothing. A proxy in front may set a lower limit. |
| U34 | Forwarded headers with invalid values (an unparsable address, a scheme other than http or https, a host or prefix with path characters) are ignored and logged once. The `Forwarded` header is ignored, as before. | fix | Fix the proxy configuration if the log names it. |

### Sign-in and accounts

| # | Change | Kind | What to do |
|---|---|---|---|
| U35 | Passwords may be up to 1024 bytes (3.3: 72). New passwords are stored with Argon2id; existing bcrypt hashes keep working and are converted at the next sign-in. Until every account has signed in once, a failed sign-in costs one Argon2id and one bcrypt check. | decided | Nothing. |
| U36 | API calls without a valid session get 401 with a JSON body instead of a redirect to the sign-in page. Pages still redirect. | fix | Scripts that followed the redirect must handle 401. |
| U95 | Removing an account's administrator rights takes effect at once: its open administration pages are refused at the next request, its pending administrator confirmations are dropped, and its live connection reconnects (close code 4004) with the new rights. The account stays signed in; terminals and tmux sessions keep running. 3.3 only cleared the flag. | fix | Nothing. |
| U37 | Uploading, replacing or deleting an SSH key and deleting a host key need a step-up confirmation unless the user signed in a moment ago. | decided | Nothing. |
| U38 | LDAP: a search with more than one match is refused with 401 (3.3: 503); a base DN below a referral answers 503; referrals are never followed. LDAP connections need TLS 1.2 or later. | fix | Make the user filter unique; update old directory servers to TLS 1.2. Prefer `entryUUID` or `objectGUID` as the subject attribute. |
| U39 | LDAP: an unusable bind-password file, CA file or filter no longer stops WebSSH from starting. The LDAP feature is shown as "not ready" in the log and in Administration, and its sign-in answers 404. | fix | Check the LDAP status after the update. |
| U40 | OIDC: a rejected ID token answers 400 "Invalid or expired OIDC login" (3.3: 503). An ID token is required; there is no fallback to the user-info endpoint. Signatures must use RS, PS, ES or EdDSA algorithms, RSA keys 2048 to 8192 bits. With the security feature `oidc` switched off, all OIDC routes answer 404. Sign-ins in progress during a restart must be started again. | fix | Make sure the provider signs ID tokens with an asymmetric key. |
| U41 | GitHub: a callback with a repeated `state`, `code` or `error` parameter is refused with 400. Accounts created through GitHub have no local password; after unlinking they sign in with a passkey. | fix | Nothing. |
| U42 | Deleting an account writes a verified copy of its rows to `DATA_DIR/go/deleted_users/<id>-<UTC>/`. Copies are kept until an operator removes them. | decided | Remove old copies by hand when they are no longer needed. |
| U43 | The routes `/api/totp/disable`, `/api/credentials/apply`, `/api/credentials/lock` and `/api/automation/vault/*` are removed; they had no caller in the interface. Two-factor sign-in is turned off from the account security page as before. | removed | Scripts that called them must use the interface. |

### SSH connections and hosts

| # | Change | Kind | What to do |
|---|---|---|---|
| U44 | Legacy algorithms (`diffie-hellman-group14-sha1`, `diffie-hellman-group-exchange-sha1`, `aes128-cbc`, `3des-cbc`, `hmac-sha1`, RSA signatures with SHA-1) are offered only with the legacy setting and at the lowest priority. An upgraded installation keeps them for all hosts; a new installation offers a per-host and per-jump-host option "Allow legacy SSH algorithms". | decided | Turn the setting off once no host needs it. |
| U45 | Not supported at all: the ciphers `aes192-cbc` and `aes256-cbc`, the MACs `hmac-md5` and `hmac-sha1-96`, Diffie-Hellman group 1, `arcfour` and DSA keys. RSA keys shorter than 1024 bits cannot be used; the migration keeps them as unusable and names them in the report. OpenSSH has refused such RSA keys since 7.6. Encrypted PKCS#8 keys are refused with their own message. | decided | Update the servers concerned; replace weak or DSA keys. |
| U46 | Passphrase-protected OpenSSH and PEM keys can be uploaded. WebSSH asks for the passphrase once and stores the key encrypted with its own key, never the passphrase. | new | Nothing. |
| U47 | A host that presents a key of another type than the trusted one is reported as `host_key_changed` at once; a revoked key is reported as `host_key_revoked`. | fix | Review and trust the new key. |
| U48 | A damaged line in a user's or the global known_hosts makes WebSSH refuse that file, naming the line. Lines end only at `\n`, `\r` or `\r\n`. | fix | Correct or remove the named line. |
| U49 | Connection errors carry stable codes and fixed texts instead of the 3.3 free text, for example no more "Jump host connection failed" catch-alls. | fix | Nothing. |
| U50 | Keepalive expects an answer; a peer that stops answering ends the session. | decided | Nothing. |
| U51 | When the WebSSH host is a tailnet node, a new installation refuses ordinary SSH (password or key) to tailnet addresses whether or not Tailscale SSH is enabled. An upgraded installation keeps the 3.3 behaviour and warns at every start while Tailscale SSH is off and the interface exists. | decided | Review the saved hosts that reach tailnet nodes with ordinary SSH; see [Tailscale SSH](Tailscale-SSH). |
| U52 | Tailscale SSH binds its connection to `TAILSCALE_SSH_INTERFACE` with `SO_BINDTODEVICE`. The `IP_UNICAST_IF` option 3.3 used is ignored by Linux for TCP, so 3.3 could reach a host over another interface. | fix | Nothing. |
| U53 | SSH gateway: a gateway that asks for a password and then a one-time code now asks for both in the browser when no password is saved. | fix | Nothing. |
| U54 | Saved password checks: a SOCKS5 proxy whose saved password no longer matches its target reports `credential_target_changed` (3.3: `connection_cancelled`). The saved password is checked again right before it is sent. | fix | Confirm the password for the new target. |
| U55 | Host discovery and the reachability check are separate permissions. On a new installation only administrators have them; administrators can grant them to all users in Administration (`host_discovery_users`, `host_reachability_users`). Upgraded installations keep them for everyone. `HOST_DISCOVERY_ENABLED=false` still turns discovery off for everyone. | decided | Review the switches. |
| U56 | The reachability check counts a host as reachable only when it answers as an SSH server; other open ports count as unreachable. A saved SOCKS5 proxy is used for the check. | decided | Nothing. |
| U57 | Discovery refuses IPv6 networks with a scope (`fe80::1%eth0`); 3.3 accepted them and lost the scope. | fix | Use an address without scope. |
| U58 | Quick SFTP uses the same connection rules as the terminal: it asks about an unknown host key, supports jump hosts and SOCKS5 and uses `SSH_CONNECT_TIMEOUT`. A changed host key is still refused. Quick SFTP over Tailscale SSH remains unsupported. | decided | Nothing. |
| U59 | A host import file with `NaN`, `Infinity` or more than 512 levels of nesting is refused with "Invalid JSON document.". | fix | Export the file again from WebSSH. |
| U60 | A failed step-up for a global host key (invalid entry, unknown id) no longer uses up the confirmation. | fix | Nothing. |

### Terminal

| # | Change | Kind | What to do |
|---|---|---|---|
| U61 | New tmux session names are at most 190 characters, so a reattach never refuses a name WebSSH created. Reattaching without a display name keeps the stored one. | fix | Nothing. |
| U62 | A connection that keeps sending terminal input or acknowledgements the server drops unread (for a closed terminal or out of order, more than 1024 frames in a row) is closed with code 4002 and reconnects. | new | Nothing. |
| U99 | Server management lists every systemd service and Docker container of the host. 3.3 dropped the first one of each list and showed, for example, "Showing 3 of 4 containers". | fix | Nothing. |

### Files, SMB and transfers

| # | Change | Kind | What to do |
|---|---|---|---|
| U63 | The SFTP preview shows text that is not UTF-8 as Latin-1 instead of reporting a binary file, like the editor and the SMB preview. | decided | Nothing. |
| U64 | File errors show fixed texts with the 3.3 codes, never the server's own message. Too large and binary files in the editor report `FILE_TOO_LARGE` and `FILE_BINARY`. Relative paths and paths with control characters are refused; names that are not valid UTF-8 are listed but cannot be opened. | fix | Nothing. |
| U65 | Quick SFTP and SMB sources belong to the browser session that opened them; another session of the same user does not see them. | fix | Nothing. |
| U93 | After a reload, the file panel of a restored terminal session offers Unix permissions (chmod) only when this browser session already opened the session's SFTP source; 3.3 offered it once any browser session had used SFTP on the connection. The permissions of a source that is actually open are unchanged. | fix | Open the file panel once; chmod then appears as before. |
| U66 | Folder downloads are streamed as ZIP instead of being built in a temporary file first. WebSSH builds every archive itself; the remote `zip` command is no longer used. A limit that is only exceeded while streaming (a file grows) ends the download instead of returning an error. ZIP entries carry each file's modification time. Downloads send their size up front; a file that shrinks or grows while it is read ends the download. | fix | Nothing. |
| U67 | Transfer links are valid once, for 300 seconds and only in the browser session that requested them. | fix | Nothing. |
| U68 | Folder downloads no longer reserve the `QUOTA_TEMP_BYTES_*` quota; each archive stays limited to the smaller of `MAX_ZIP_DOWNLOAD_SIZE` and `QUOTA_TEMP_BYTES_PER_USER`. | fix | Nothing. |
| U69 | SMB follows the same network policy as SSH: loopback and tailnet addresses are allowed unless `BLOCK_INTERNAL_SSH=true`. `SMB_ALLOWED_TARGETS` stays an exact allowlist. Share enumeration is removed. Windows status codes that 3.3 reported as `OPERATION_FAILED` now get specific codes, and on Windows servers a rename or upload whose reply was lost is reported as done when it took effect. | decided | Check `SMB_ALLOWED_TARGETS` if you relied on the stricter 3.3 address check. |

### Saved passwords and automation

| # | Change | Kind | What to do |
|---|---|---|---|
| U70 | The old passphrase-protected automation vault (before 3.0) is kept unchanged and can only be imported. The import button is shown until the vault has been imported. Entries for hosts behind a jump host or SOCKS5 proxy show as changed after the import. | decided | Import the vault with its passphrase, then confirm the changed entries. |
| U71 | Runbooks use saved passwords only; the password prompt of a run is a step-up confirmation. Runs are refused with `unsupported_target` for hosts behind an SSH gateway, Tailscale SSH, a SOCKS5 proxy or more than one jump host, and for usernames with `:`. Every hop needs a trusted host key. | fix | Move such hosts out of runbooks or connect them directly. |
| U72 | When the first check of a run fails, its targets are `skipped` and the run is `failed` (3.3: `unknown`). | fix | Nothing. |
| U73 | Schedule approvals are checked with the 3.3 rules during the migration. Valid ones stay approved; invalid ones become `stale` with a reason, and schedules that were running at the time of the update are paused as `unknown`. | decided | Review and approve the schedules the report lists. |
| U74 | Background jobs keep their state across restarts: a periodic job continues from its last run, a run missed during downtime runs once, and an interrupted run is reported and not repeated. | new | Nothing. |
| U75 | A runbook library with more than 100 runbooks is migrated in full and reported as `runbook_above_limit`; new runbooks need room below the limit. | decided | Remove unused runbooks. |
| U98 | A connection that would use a saved password over plain HTTP is refused with the code `https_required` (3.3: `authentication_required`); the page still shows "Password management requires HTTPS." | fix | Serve WebSSH over HTTPS, or through a TLS proxy listed in `TRUSTED_PROXY_CIDRS`, to use saved passwords. |

### Backup, restore and secret rotation

| # | Change | Kind | What to do |
|---|---|---|---|
| U76 | Backups are tar archives in the format `webssh-go-backup`, named `webssh-backup-<UTC>.tar`. The browser download is still saved as `webssh-backup.zip`, but its content is tar. | decided | Keep the archives; do not unpack them with ZIP tools. |
| U77 | 3.4 backups cannot be restored with 3.3. 3.3 backups (format v1 and v2, exports, online backups and recovery snapshots) restore on 3.4 through the same migration as the first start. | decided | Keep a 3.3 backup until the way back is no longer needed. |
| U78 | Restoring a 3.4 archive takes over the archive's `SECRET_KEY` when the active key comes from `DATA_DIR/secret_key` and no 3.3 data is left (after `webssh legacy purge`, or on an installation that never ran 3.3). While the 3.3 data still exists, `DATA_DIR/secret_key` and the keyring material are never changed: the archive's secrets are sealed again under the active key, so the way back to 3.3 keeps working. When `SECRET_KEY` is set in the environment and differs from the archive's key, the restore is refused before anything changes. 3.3 restored such an archive and could then not read its secrets. | fix | Restore with the `SECRET_KEY` the archive was made with, or let WebSSH manage the key file. |
| U79 | After a web restore WebSSH restarts inside the running process instead of exiting. | fix | Nothing; the container keeps running. |
| U80 | A restore ends every sign-in, step-up confirmation, bootstrap code and known-device cookie, and every schedule needs a new approval. | decided | Sign in again; approve schedules. |
| U81 | `backup create --without-secret-key` leaves out `SECRET_KEY`. The keyring material stays in the archive; the restore then needs the same `SECRET_KEY` on the target. | decided | Store the key separately when you use the option. |
| U82 | 3.4 archives are checked strictly before a restore: links, devices, absolute or non-canonical paths, `..`, backslashes, members missing from the manifest and members below `go/` or `logs/` are refused. 3.3 archives are read as tolerantly as before. | decided | Nothing. |
| U83 | The restore state lives in `DATA_DIR/go/restore-status.json`, next to the data, instead of in `BACKUP_TEMP_DIR`. Online restore no longer requires `BACKUP_RECOVERY_DURABLE=true`. | fix | Nothing. |
| U84 | `rotate-secret-key --confirm-offline` refuses while a WebSSH server uses the data directory and while the 3.3 data still exists. The recovery snapshot before the rotation is a 3.4 archive (`webssh-backup-<UTC>.tar`) instead of `<datadir>-pre-rotation-….zip`. Besides all browser sessions, a rotation also ends enrollments, two-factor sign-ins and passkey ceremonies in progress, step-up confirmations and open bootstrap codes. A rotation interrupted by a crash completes at the next start. | fix | Run `legacy purge` before the first rotation; stop the server. |

### Administration and audit

| # | Change | Kind | What to do |
|---|---|---|---|
| U85 | 3.4 writes to the same `logs/security_audit.log` as 3.3, in the same line format. After a way back, the 3.3 log contains the 3.4 entries. | decided | Nothing. |
| U86 | Entering maintenance (backup restore, rotation, a changed 3.3 source) closes every live connection with code 4503; `/ready` answers 503. | fix | Nothing. |
| U87 | The operations view lists the background jobs of the new server and their state. Python worker threads and the HTTP thread reserve no longer exist; `http_reserve` is always 0. Disconnecting a live connection as an administrator closes it without automatic reconnect. | fix | Nothing. |
| U88 | `connection-store list` and `delete` also work while the server runs; `--confirm-offline` is still required. | fix | Nothing. |

### Appearance

| # | Change | Kind | What to do |
|---|---|---|---|
| U97 | In the Glass theme, primary buttons turn a darker blue on hover (`#0866b0` instead of `#087dcf`), so white text keeps a contrast of at least 4.5:1; 3.3 reached 4.3:1. | fix | Nothing. |
| U100 | Overview host cards form an even grid: the cards of a row have the same height and their status and actions sit at the bottom on one line. The machine badge (VM, LXC, Bare Metal) hangs below the platform tile instead of covering its edge. Host profile and Configuration readiness no longer unfold inside the card; a click on the logo or name of a card opens them as a popover, on a phone as a sheet at the bottom. A panel with a stored height draws a rule under its heading while its content scrolls. | fix | Nothing. |

### HTTP API

The JSON API under `/api/` is internal and serves the web interface. Scripts
that call it directly see these changes:

| # | Change | Kind |
|---|---|---|
| U89 | Every JSON error has the form `{"success": false, "code": "…", "error": "…"}`; texts are unchanged. An unknown API path answers JSON 404 instead of an HTML page, and an oversized body 413 with the code `too_large`. | fix |
| U96 | A request body is read only after the session and the access level were checked: a request without the needed session gets 401 or 403 without its body being read. Sign-in, registration and passkey sign-in bodies may be at most 16 KiB. While the server holds its maximum of buffered request bodies (64 MiB for signed-in users, of which one account holds at most 8 MiB across all its sessions, and 16 MiB without a session), a request waits up to 5 seconds and then gets 503 `unavailable` with `Retry-After`. | fix |
| U90 | Request bodies are read strictly: duplicate member names, `NaN`, `Infinity`, lone surrogates and trailing data are refused with 400 in most routes. A TOTP code must be a JSON string. | fix |
| U91 | Routes and live events without a caller in the interface are removed (`U43`, and the file events `check_exists` and `get_file_stat`). | removed |

## Known limits

These limits apply to 3.3 and 3.4 alike or are open for a later release:

- At most 10 SSH sessions run at the same time, 5 per account
  (`QUOTA_SSH_SESSION_GLOBAL`, `QUOTA_SSH_SESSION_PER_USER`). Two accounts
  with five sessions each lock everyone else out. Raise the limits for more
  users.
- A detached terminal whose program keeps printing stays open until its
  owner signs out, because output counts as activity.
- Audit entries for Tailscale SSH do not include the client address yet,
  and attempts through the SSH gateway count against the SSH session quota.
- Tailscale SSH has been tested against a stand-in for tailscaled, not
  against a real tailnet.

## Way back to 3.3

The way back is the 3.3 image on the unchanged data volume. It exists until
you run `webssh legacy purge`.

1. Stop and remove the 3.4 container.
2. Start the last 3.3 image (pin its tag, for example `3.3.0`) with the
   same volumes and the 3.3 Compose file.

3.3 finds its data as it was before the update. Everything done in 3.4
after the update is missing there: new accounts, hosts, keys, settings and
changed passwords. 3.4 backups cannot be restored with 3.3 (`U77`); keep
the 3.3 backup you made before the update.

While 3.3 runs again:

- It treats `DATA_DIR/go/` as ordinary data and includes it in its backups.
  The secrets in that database stay unreadable without
  `logs/.webssh-go/keyring-material`, which 3.3 never packs.
- Do not delete `go/` or `logs/.webssh-go/` if you may upgrade again.
- `logs/security_audit.log` contains the entries 3.4 wrote (`U85`).
- The variables 3.4 introduced, such as `TRUSTED_PROXY_CIDRS`, have no
  effect in 3.3.

### Starting 3.4 again after the way back

3.4 compares the 3.3 data with the state it migrated. If 3.3 changed
anything, 3.4 does not start and names the command that migrates again:

```bash
docker compose stop webssh
docker compose run --rm webssh migrate --replace
docker compose up -d
```

`migrate --replace` keeps the current 3.4 database as a verified backup in
`DATA_DIR/go/` and migrates the 3.3 data again. Changes made in 3.4 before
the way back are replaced. If a 3.3 restore removed `go/`, 3.4 reports that
its data is missing and names the same command.

## Removing the 3.3 data

Once you no longer need the way back, remove the 3.3 data from the volume:

```bash
docker compose stop webssh
docker compose run --rm webssh legacy purge --backup-to /app/recovery
docker compose up -d
```

- Remove it as soon as the way back is no longer needed, in particular when
  the migration report warns `plaintext_key_sealed`: older 3.x versions kept
  some SSH keys unencrypted, and those files stay in the 3.3 data until the
  purge.
- The command refuses while a server or 3.3 runs on the volume, before a
  completed migration and while the report still lists data a later release
  has to take over.
- It lists the paths it will remove, including left-over directories the
  migration kept in place, and asks for confirmation (`--yes` skips the
  question, not the list).
- Before it removes anything it writes a backup with the 3.4 database,
  `SECRET_KEY`, the keyring material and every left-over 3.3 file, reads it
  back and prints its path. Without `--backup-to` it writes next to
  `DATA_DIR` when that directory is writable, otherwise to
  `BACKUP_TEMP_DIR`. `--skip-backup` is refused while left-over files exist.
- The backup is not encrypted and has mode 0600. Whoever can read it can
  read every stored secret. Move it off the host.
- `secret_key`, `logs/` and `go/` are never removed. The keyring material
  moves from `logs/.webssh-go/` to `go/keyring-material`.
- An interrupted purge continues at the next start.

After the purge the way back to 3.3 is gone. `rotate-secret-key` is
available from then on.

## See also

- [Operations guide](https://github.com/bifrost0x/webssh/blob/main/docs/operations-guide.md):
  running, checking and recovering the Go server.
- [Backup, Restore, and Secret Rotation](Backup-Restore-and-Secret-Rotation)
- [Upgrading, Rollback, and FAQ](Upgrading-Rollback-and-FAQ)
- [Data Storage and Persistence](Data-Storage-and-Persistence)
