# Go package map

This map defines the packages of the Go backend, what each one owns and
which imports are allowed. It is derived from what WebSSH offers its users,
admins and operators, not from the structure of the Python application
([ADR 0006](../adr/0006-capability-driven-redesign.md)). The rules behind it
are in [ADR 0003](../adr/0003-package-structure-and-modularity.md).

The **Packages** table is machine-checked: `internal/architecture` fails when
it differs from the package map in `internal/architecture/packagemap_test.go`.
Packages that do not exist yet are listed so that the structure is agreed
before the code is written. The phase column names the build phase that
creates the package (G0, B1 to B8 of the project plan; M1 for the preview
milestone, M2 for the parity milestone). The contracts between the packages
built for M1 are in [m1-contracts.md](m1-contracts.md), those of M2 in
[m2-contracts.md](m2-contracts.md).

Packages whose name ends in `test` hold test doubles. The architecture
tests allow only test files to import them.

The Go backend is built in parallel to the Python application and has its
own data model ([ADR 0002](../adr/0002-parallel-build-with-one-time-migration.md)).
Existing installations are carried over once, automatically, by
`internal/migrate/legacy` ([ADR 0007](../adr/0007-legacy-data-migration.md)).

## Capabilities

| Capability (user view) | Go packages |
|---|---|
| Sign-in and identity: local passwords, LDAP/AD, OIDC, GitHub, second factors, recovery, step-up, known devices, roles and permissions | `internal/auth`, `internal/auth/*`, `internal/accounts`, `internal/otp`, `internal/qrcode`, `internal/ldapproto` |
| Browser sessions: issue, expire, revoke | `internal/session` |
| Hosts: saved hosts and profiles, jump hosts, host identity, platform facts, profile exchange, outbound network policy | `internal/hosts`, `internal/ssh/hostkey`, `internal/netpolicy` |
| Host operations: server operations, discovery, runtime inventory, host context and notes, session insights | `internal/hostops` |
| Terminal: interactive SSH, startup and post-connect commands, persistent sessions | `internal/terminal`, `internal/ssh/client` |
| Remote commands: one bounded way to run a command on a host | `internal/ssh/remotecmd` |
| Files: one workspace over SFTP and SMB, editor | `internal/files`, `internal/files/sftp`, `internal/files/smb` |
| Transfers: uploads, downloads, host-to-host copies | `internal/transfer` |
| Secrets: credentials, keys, automation vault, encryption at rest | `internal/vault`, `internal/keyring` |
| Commands and settings | `internal/commands`, `internal/settings` |
| Automation: scheduled and permission jobs | `internal/automation`, `internal/cron`, `internal/jobs` |
| SSH gateway (WebSSH is the client) and Tailscale SSH | `internal/ssh/gateway`, `internal/ssh/tailscale` |
| Operation: backup, restore, secret rotation, maintenance, diagnostics, feature gates, admin CLI | `internal/backup`, `internal/operations`, `internal/admincli` |
| Audit | `internal/audit` |
| Limits: connection and storage quotas | `internal/quota` |
| Platform (Linux: Docker, Unraid): data directory permissions, time zone check | `internal/platform` |
| Upgrade from the Python release: one-time migration of `DATA_DIR`, restore of Python backups, removal of legacy data | `internal/migrate/legacy`, `internal/fernet` |
| Runtime: process, HTTP, realtime | `cmd/webssh`, `internal/httpapi`, `internal/realtime`, `internal/realtime/protocol`, `internal/config`, `internal/store`, `internal/fault`, `internal/principal`, `internal/buildinfo` |
| Testing: test doubles and the end-to-end seed | `internal/principal/principaltest`, `internal/realtime/protocol/protocoltest`, `internal/store/storetest`, `internal/auth/authtest`, `internal/backup/backuptest`, `internal/e2eseed` |

## Packages

Kinds and allowed imports ([ADR 0003](../adr/0003-package-structure-and-modularity.md)):

- **entry** (`cmd/…`) may import every internal package.
- **foundation** imports only the standard library, allowlisted modules and other foundation packages.
- **capability** imports foundation packages, its own ancestors (`internal/files/smb` may import `internal/files`) and the packages in *May also import*. Never an edge package.
- **edge** imports foundation and capability packages, and other edge packages only when listed.

| Package | Kind | Responsibility | May also import | Phase |
|---|---|---|---|---|
| `cmd/webssh` | entry | Wiring and subcommands only; under the path `/app/entrypoint.sh` it also accepts the deprecated `flask --app start:app …` form until the next major release ([ADR 0011](../adr/0011-http-api-and-cli-surface.md)) | – | G0 |
| `internal/architecture` | foundation | Structural rules as tests (no production code) | – | G0 |
| `internal/buildinfo` | foundation | Release version and source revision of the binary | – | G0 |
| `internal/config` | foundation | Configuration from the documented environment variables, `DATA_DIR`, `SECRET_KEY`; same results as the Python parser with warnings for odd forms, list of variables accepted without effect ([ADR 0007](../adr/0007-legacy-data-migration.md)) | – | B1 |
| `internal/store` | foundation | SQLite access, transactions, versioned schema migrations; the only store for user data (no per-user files), each capability owns its tables | – | B1 |
| `internal/fernet` | foundation | Fernet tokens (tier C, official vectors), read only by the legacy migration | – | B1 |
| `internal/keyring` | foundation | Per-purpose keys from `SECRET_KEY` (HKDF), AEAD for every secret Go writes, rotation, browser-local namespace derivation ([ADR 0008](../adr/0008-keyring-for-secrets-at-rest.md)) | – | B1 |
| `internal/fault` | foundation | One error model: the catalog of stable codes, safe messages and their HTTP status, used by every transport ([M1 contracts](m1-contracts.md)) | – | B1 |
| `internal/principal` | foundation | Who acts: the principal of a request or connection in the context, session revocations, the step-up action catalog ([M1 contracts](m1-contracts.md)) | – | M1 |
| `internal/otp` | foundation | HOTP/TOTP (RFC 4226/6238, tier C) | – | B2 |
| `internal/qrcode` | foundation | QR code generation for enrolment (tier C) | – | B2 |
| `internal/ldapproto` | foundation | LDAP subset client, only if self-written (decided in B2) | – | B2 |
| `internal/realtime/protocol` | foundation | Versioned realtime envelope, binary frames, close codes and the message type catalog, decoded strictly ([M1 contracts](m1-contracts.md)) | – | M1 |
| `internal/principal/principaltest` | foundation | Test doubles: step-up service and revocation feed; imported by test files only | – | M1 |
| `internal/realtime/protocol/protocoltest` | foundation | Test double of a realtime connection for capability handlers; imported by test files only | – | M1 |
| `internal/store/storetest` | foundation | Throw-away databases for store tests; imported by test files only | – | M1 |
| `internal/cron` | foundation | Cron expressions and schedules (tier C) | – | B6 |
| `internal/platform` | foundation | Data directory owner and mode, time zone check (Linux only) | – | B8 |
| `internal/pyjson` | foundation | JSON text as the Python release reads and writes it: duplicate member names (last wins), escaped lone surrogates, exact number texts, `ensure_ascii` strings; shared by the legacy migration and the settings import | – | M1 |
| `internal/naming` | foundation | Comparison form of the names users give saved hosts, jump hosts, SOCKS5 proxies, SSH keys and saved passwords (trimmed, case-folded); unique per user from 3.4 (U100) | – | M2 |
| `internal/session` | capability | Browser sessions: issue, validate, expire, revoke | – | B2 |
| `internal/accounts` | capability | Users, administrators (`ADMIN_USERS`), roles and permissions (including host discovery), account lifecycle | `internal/session` | B2 |
| `internal/auth` | capability | Sign-in flow, provider and factor registries, known devices, assurance, recovery, in-process rate limits, one way to turn off a second factor | `internal/session`, `internal/accounts` | B2 |
| `internal/auth/stepup` | capability | Action-bound step-up: action catalog, grants bound to user, session and action ([ADR 0011](../adr/0011-http-api-and-cli-surface.md)) | `internal/session` | B2 |
| `internal/auth/local` | capability | Password sign-in, Argon2id hashing, bcrypt verification and rehash ([ADR 0009](../adr/0009-password-hashing.md)) | – | B2 |
| `internal/auth/ldap` | capability | LDAP and Active Directory sign-in | – | B2 |
| `internal/auth/oidc` | capability | OpenID Connect sign-in | – | B2 |
| `internal/auth/github` | capability | GitHub sign-in | – | B2 |
| `internal/auth/totp` | capability | TOTP second factor | – | B2 |
| `internal/auth/webauthn` | capability | Passkeys | – | B2 |
| `internal/audit` | capability | Audit events, retention and export | – | B2 |
| `internal/netpolicy` | capability | One policy for all outbound targets (roles `ssh`, `smb`, `socks`, `probe`; shared address classes; unrestricted by default, optional restriction via `BLOCK_INTERNAL_SSH`), resolve and admit once, tailnet rule independent of the Tailscale SSH switch ([ADR 0010](../adr/0010-outbound-network-policy.md)) | – | B3 |
| `internal/quota` | capability | Connection and storage quotas behind one policy mechanism | – | B3 |
| `internal/ssh/client` | capability | The only SSH dialer (terminal, Quick SFTP, automation, gateway, reachability probe): authentication, keys, jump hosts, SOCKS5, host key check | `internal/netpolicy` | B3 |
| `internal/ssh/hostkey` | capability | Known host keys and fingerprints | – | B3 |
| `internal/ssh/remotecmd` | capability | Run one command on a connected host with time, output and input limits | `internal/ssh/client` | B3 |
| `internal/terminal` | capability | Interactive shells: output flow, input budget, startup and post-connect commands, persistent tmux session names | `internal/ssh/client`, `internal/ssh/hostkey`, `internal/ssh/remotecmd` | B3 |
| `internal/hosts` | capability | Saved hosts and profiles, host catalog and identity, platform facts, profile exchange, workspace presets | `internal/ssh/client`, `internal/ssh/remotecmd` | B3 |
| `internal/hostops` | capability | Server operations, discovery and reachability check behind their permission, runtime inventory, host context, notes (one model: saved host or none), session insights (M1: the note without a host and the minimal overview status) | `internal/ssh/client`, `internal/ssh/remotecmd` | B3 |
| `internal/ssh/gateway` | capability | Connections through an SSH gateway such as Warpgate (WebSSH is the client): selector, authentication strategy, browser prompts and readiness probe as a variant of the shared dialer | `internal/ssh/client`, `internal/ssh/hostkey` | B3 |
| `internal/ssh/tailscale` | capability | Tailscale SSH targets and shared-identity policy | `internal/ssh/client`, `internal/netpolicy` | B3 |
| `internal/files` | capability | Protocol-neutral file workspace, editor, backend registry, one preview path with the editor's decoding rule for SFTP and SMB | – | B4 |
| `internal/files/sftp` | capability | SFTP file backend | `internal/ssh/client`, `internal/ssh/remotecmd` | B4 |
| `internal/files/smb` | capability | SMB file backend, pool and diagnostics | `internal/netpolicy` | B4 |
| `internal/transfer` | capability | Uploads, downloads, progress, host-to-host copies | `internal/files` | B4 |
| `internal/vault` | capability | Credentials, SSH keys, import of the legacy automation vault with the user's passphrase | – | B5 |
| `internal/commands` | capability | Commands and command sets | `internal/ssh/remotecmd` | B6 |
| `internal/automation` | capability | Automations and permission jobs | `internal/ssh/client`, `internal/ssh/remotecmd`, `internal/vault` | B6 |
| `internal/settings` | capability | Application and user settings, terminal appearance, onboarding | – | B1 |
| `internal/auth/authtest` | capability | Test doubles of the external identity contracts (redirect provider, identity links, revalidator); imported by test files only | – | M2 |
| `internal/backup/backuptest` | capability | Test doubles of the maintenance switch and the restorer of Python backups; imported by test files only | – | M2 |
| `internal/backup` | capability | Go backup format (versioned manifest, SQLite, optional `SECRET_KEY`), strict restore, online backup, secret rotation, maintenance mode | – | B7 |
| `internal/operations` | capability | Diagnostics, support report, security feature gates (M1: feature gates and their impact preview only) | – | B7 |
| `internal/httpapi` | edge | HTTP server, routing, middleware (session, CSRF, origin, client address from `TRUSTED_PROXIES` and `TRUSTED_PROXY_CIDRS`, limits), health, static files and frontend | – | B1 |
| `internal/jobs` | edge | Background job registry, single-owner execution | – | B1 |
| `internal/migrate/legacy` | edge | One-time, verified migration of a Python `DATA_DIR` and of Python backups (lenient paths); registry of steps per entity; `migrate --replace` and `legacy purge` | – | B1 |
| `internal/realtime` | edge | Native WebSocket endpoint, same-origin and allowlist check on every upgrade, connection lifecycle, dispatch | – | B3 |
| `internal/admincli` | edge | Administrator subcommands of `webssh` | – | B7 |
| `internal/idna2003` | foundation | IDNA 2003 host name conversion as the Python release applied it (`encodings.idna`), so the network policy sees one canonical form of every host ([M2 contracts](m2-contracts.md)) | – | B3 |
| `internal/files/filestest` | capability | Test double: an in-memory file backend; imported by test files only | – | B4 |
| `internal/vault/vaulttest` | capability | Test double of the saved-password provider; imported by test files only | – | B5 |
| `internal/e2eseed` | edge | Applies the end-to-end seed to the Go stores and provides the test-only hooks; imported only by `cmd/webssh/e2e.go` (build tag `e2e`), never part of the release binary | – | M1 |

`internal/migrate/legacy` is the only package that knows the Python schema
and file layout. It reads them and writes through the capabilities' stores.
The framework comes in B1; every later phase adds the steps for its
entities. The package is removed once direct upgrades from the last Python
release are no longer supported.

Go reads Python formats only during the migration
([ADR 0007](../adr/0007-legacy-data-migration.md)). `internal/fernet`
implements the Fernet format for that purpose; Go itself writes every
secret through `internal/keyring`
([ADR 0008](../adr/0008-keyring-for-secrets-at-rest.md)). The import of
the legacy automation vault in `internal/vault` is the one runtime reader of
a legacy format, because only the user's passphrase opens it.

There is no local file backend: the Python application has none. The file
backend registry allows one to be added later as `internal/files/local`.

## Extension points

Each extension point has a small interface defined by the package that
consumes it and a registry in the same package. Implementations are
registered in `cmd/webssh`. The interfaces use only standard library and
foundation types, so implementing them needs no import of the consumer's
kind-restricted peers.

| Extension point | Interface and registry | Implementations |
|---|---|---|
| File backends | `internal/files` | `internal/files/sftp`, `internal/files/smb` |
| Sign-in providers | `internal/auth` | `internal/auth/local`, `internal/auth/ldap`, `internal/auth/oidc`, `internal/auth/github` |
| Second factors | `internal/auth` | `internal/auth/totp`, `internal/auth/webauthn` |
| Realtime message types | contract and catalog in `internal/realtime/protocol`, registry in `internal/realtime` | capability packages, in their `realtime.go` file |
| Background jobs | `internal/jobs` | capability packages (automation, backup, audit retention) |
| Migration steps per entity (read, write, verify) | `internal/migrate/legacy` | one file per entity in `internal/migrate/legacy` |

Wiring across kinds:

- **Python backups.** `internal/backup` declares the restore interface it
  needs for a legacy archive; `internal/migrate/legacy` implements it and
  `cmd/webssh` connects the two. `backup` never imports the edge package.
- **Audit, quotas, feature gates, step-up, permissions.** Consumers declare
  small interfaces; `cmd/webssh` passes `internal/audit`, `internal/quota`,
  `internal/operations`, `internal/auth/stepup` or `internal/accounts`
  values. No cross-capability import is needed.
- **HTTP and realtime.** Capabilities never import `internal/httpapi` or
  `internal/realtime`. They expose handlers on `net/http` in `http.go` or
  `http_*.go`, which also hold outbound HTTP clients (OIDC, GitHub API), and
  realtime handlers against `internal/realtime/protocol`; the edge packages
  mount them.

## Python modules by Go package

This list exists so that nothing is forgotten. It is not a template: each
capability is re-designed from its user-facing behaviour and data
contracts, and each old rule is classified as keep, fix, drop or decide
([ADR 0006](../adr/0006-capability-driven-redesign.md)). Data of every
module is also read by `internal/migrate/legacy`.

| Go package | Python today (`app/` unless noted) | Phase |
|---|---|---|
| `cmd/webssh`, `internal/config` | `config.py`, `start.py`, `entrypoint.sh` | B1 |
| `internal/httpapi` | `__init__.py`, `health.py`, `static_delivery.py`, `request_limits.py`, `transport_security.py`, `decorators.py`, `auth_redirects.py` | B1 |
| `internal/jobs` | `runtime_lifecycle.py` | B1 |
| `internal/buildinfo` | `version.py` | G0 |
| `internal/store`, `internal/migrate/legacy` | `models.py`, `storage_migrations.py`, `storage_utils.py` | B1 |
| `internal/fault` | `ssh_errors.py`, `storage_errors.py`, `transfer_errors.py` | B1 |
| `internal/keyring`, `internal/fernet` (legacy reading in `internal/migrate/legacy`) | `key_encryption.py`, `credential_crypto.py`, `mfa_crypto.py`, `github_auth_crypto.py` | B1 |
| `internal/settings` | `app_settings.py`, `user_settings.py`, `terminal_appearance.py`, `onboarding.py` | B1 |
| `internal/session` | `session_epoch.py`, `account_sessions.py`, `access_revocation_queue.py`, `login_access.py`, `browser_identity.py` | B2 |
| `internal/accounts` | `user_lifecycle.py` | B2 |
| `internal/auth/stepup` | `step_up.py`, `step_up_routes.py`, `account_step_up_routes.py` | B2 |
| `internal/auth` | `auth.py`, `auth_assurance.py`, `login_devices.py`, `rate_limiter.py`, `mfa_throttle.py`, `mfa_factors.py`, `recovery_service.py`, `recovery_routes.py`, `factor_bootstrap.py` | B2 |
| `internal/auth/ldap`, `internal/ldapproto` | `ldap_service.py`, `ldap_session.py`, `ldap_routes.py` | B2 |
| `internal/auth/oidc` | `oidc_service.py`, `oidc_routes.py` | B2 |
| `internal/auth/github` | `github_auth_service.py`, `github_auth_routes.py` | B2 |
| `internal/auth/totp`, `internal/otp`, `internal/qrcode` | `totp_service.py`, `totp_routes.py` | B2 |
| `internal/auth/webauthn` | `webauthn_service.py`, `webauthn_routes.py` | B2 |
| `internal/audit` | `audit_logger.py` (B2), `audit_export.py` (B7) | B2, B7 |
| `internal/realtime`, `internal/realtime/protocol` | `socket_events.py` (dispatch and handshake; message handlers belong to their capability), `socket_capacity.py`, `socket_protocol.py` | B3 |
| `internal/ssh/client` | `ssh_manager.py` (connect), `ssh_connection_attempt.py`, `ssh_key_loader.py`, `jump_host_manager.py`, `socks5_client.py`, `socks_proxy_manager.py`, `paramiko_channels.py`, `connection_pool.py` | B3 |
| `internal/ssh/hostkey` | `host_key_store.py`, `host_key_routes.py` | B3 |
| `internal/terminal` | `ssh_manager.py` (shells), `ssh_output_flow.py`, `ssh_input_budget.py`, `startup_commands.py`, `post_connect_manager.py`, `session_directory.py` | B3 |
| `internal/netpolicy` | `network_policy.py`, `smb_network_policy.py`, route lookup of `tailscale_ssh.py` | B3, B4 |
| `internal/quota` | `quota_manager.py`, `storage_quota.py`, `connection_storage_policy.py`, `command_storage_policy.py` | B3 |
| `internal/hosts` | `host_catalog.py`, `host_platform.py`, `profile_manager.py`, `profile_exchange.py`, `profile_exchange_routes.py`, `customer_workflows.py` | B3 |
| `internal/hostops` | `server_operations.py`, `server_operations_routes.py`, `discovery_routes.py`, `runtime_inventory.py`, `session_insights.py`, `host_context.py`, `host_context_routes.py`, `herdr.py`, `overview_routes.py` | B3 |
| `internal/ssh/gateway` | `ssh_gateway.py`, `ssh_gateway_auth.py`, `ssh_gateway_interaction.py`, `ssh_gateway_setup.py` | B3 |
| `internal/ssh/tailscale` | `tailscale_ssh.py` | B3 |
| `internal/files` | `file_backend.py`, `file_service.py`, `file_sources.py`, `file_mutations.py`, `editor_text.py`, `binary_transfer.py`, `socket_file_control.py` | B4 |
| `internal/files/sftp` | `sftp_backend.py`, `sftp_handler.py`, `sftp_metadata.py` | B4 |
| `internal/files/smb` | `smb_backend.py`, `smb_protocol.py`, `smb_pool.py`, `smb_paths.py`, `smb_share_manager.py`, `smb_diagnostics.py` | B4 |
| `internal/transfer` | `transfer_manager.py`, `transfer_routes.py`, `transfer_progress.py`, `remote_transfer.py` | B4 |
| `internal/vault` | `credential_connections.py`, `credential_routes.py`, `credential_service.py`, `credential_store.py`, `automation_vault.py`, `key_manager.py` | B5 |
| `internal/commands` | `command_manager.py`, `command_set_manager.py`, `command_parameters.py`, `resources/commands/` | B6 |
| `internal/automation`, `internal/cron` | `automation_service.py`, `automation_routes.py`, `automation_schedule.py`, `automation_store.py`, `automation_transport.py`, `automation_cron.py`, `permission_jobs.py` | B6 |
| `internal/backup`, `internal/migrate/legacy` | `admin_backup.py`, `backup_manager.py`, `backup_operations.py`, `backup_coordination.py`, `online_backup.py`, `restore_service.py`, `restore_database.py`, `restore_sanitizer.py`, `secret_rotation.py`, `maintenance_mode.py`, `data_access.py` | B7 |
| `internal/operations` | `operations.py`, `support_report.py`, `security_features.py`, `security_feature_impact.py` | B7 |
| `internal/admincli` | `cli.py` | B7 |
| `internal/platform` | `entrypoint.sh` (data directory ownership), `unraid/` template behaviour | B8 |
