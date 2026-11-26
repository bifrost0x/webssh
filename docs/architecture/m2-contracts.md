# M2 contracts

This document fixes the contracts the packages of the M2 parity milestone
are built against. It extends [m1-contracts.md](m1-contracts.md); the rules
of "How contracts are fixed" there apply unchanged. The catalog tables
below (headings that start with "Error codes", "Message types" or
"Step-up actions") are joined with those of the M1 document and checked
against the code by `internal/architecture`.

The parts are written by two contract packages; each part has its own
top-level heading.

## Identity, operation, wiring and harness (V2b)

### External identity

`internal/auth` (file `external.go`, `flight.go`) defines the contract of
the external providers; the provider packages `internal/auth/ldap`,
`internal/auth/oidc` and `internal/auth/github` declare what they consume
in their `contract.go`.

- **Providers.** `auth.ProviderName` is `ldap`, `oidc` or `github`.
  LDAP is a `auth.Provider` (name and password, same timing for every
  refusal). OIDC and GitHub are `auth.ExternalProvider`:
  `Name()`, `Begin(ctx, Flight) (redirectURL, error)` and
  `Complete(ctx, Flight, Callback) (Identity, error)`. The registry of
  `internal/auth` holds them; `cmd/webssh/wire_<provider>.go` registers
  them. Every refusal is `auth_failed` without provider text; an
  unreachable provider is `unavailable`.
- **Flight.** One redirect in progress: provider, purpose (`login`,
  `link`, `step_up`, the values of the Python login state), state, nonce,
  PKCE verifier (`NewFlight`: 32, 32 and 64 random bytes as base64url, as
  `secrets.token_urlsafe`), user id, auth generation and session id for
  `link` and `step_up`, the step-up action and target, the continuation.
  The flow of `internal/auth` stores it server-side, bound to the browser
  binding, consumes it once and drops it after `auth.FlightTTL` (five
  minutes). Providers keep no per-request state. `Flight.Accept(cb, now)`
  is the first check of every callback: state compared in constant time,
  not expired, no provider error, a code present. `ParseCallback` refuses
  a repeated or oversized parameter (fuzzed). `Flight.Challenge` is S256
  (RFC 7636 vector tested). `link` and `step_up` ask the provider to
  authenticate again (`prompt=login`; for OIDC step-up also `max_age=0`
  and `OIDC_STEP_UP_ACR_VALUES`).
- **Identity.** Provider, issuer (OIDC issuer, `LDAP_PROVIDER_ID`, empty
  for GitHub), subject (OIDC `sub`, numeric GitHub id, canonical LDAP
  unique attribute), username, display name, e-mail and its verification,
  the LDAP DN, assurance and amr methods. Accounts are found only by
  `(issuer, subject)`, never by name or e-mail.
- **Mapping to accounts.** `auth.IdentityLinks` (`Account`, `Provision`,
  `LinkTx`, `Unlink`, `List`) is implemented by each provider package over
  its own table. `(issuer, subject)` is unique; an account has at most one
  identity per LDAP provider and one GitHub identity. A second link is
  `conflict`, never a move. `Account` is `not_found` for an unlinked
  identity; the caller then provisions or refuses. `Provision` follows the
  provider's policy (`LDAP_AUTO_PROVISION`; GitHub `auto_provision` with the
  organisation allowlist, which production requires) and is `forbidden`
  otherwise; OIDC never provisions. Link, unlink and provision run after
  the consumer consumed the step-up grant.
- **Managed accounts.** `accounts.Manager` stays `""`, `ldap` or
  `github` (E01). An LDAP identity makes the account LDAP-managed; a
  GitHub identity only when it provisioned the account
  (`provisioned_by_github`). OIDC never manages an account, as in
  `models.py`; the M2 plan's `managed_by = oidc` is not taken over. A
  managed account has no local password and cannot change one. Unlinking
  an LDAP identity needs a new local password (`ldap.Accounts.ReleaseTx`).
  The provisioning call of `internal/accounts` is
  `ProvisionTx(ctx, tx, username, manager string) (userID int64, error)`;
  it is binding when ID4 merges it.
- **Bootstrap.** `webssh issue-factor-bootstrap` issues a one-time code,
  valid ten minutes, bound to the account and the action, stored only as
  its MAC (`keyring.FactorBootstrap`). It is the step-up method
  `bootstrap` (C-MFA-11, ID3).
- **Step-up methods** of the external providers keep the Python names:
  `ldap`, `oidc`, `github`, `bootstrap`. The redirect providers complete a
  step-up through `StepUpProofs.ProveExternal(ctx, p, intent, method,
  assurance) (grant, error)`, which `internal/auth/stepup` provides (ID2).
- **Revalidation.** `auth.Revalidator.Revalidate(ctx, userID)` re-checks an
  LDAP account against the directory every
  `LDAP_SESSION_REVALIDATION_SECONDS`, as a job and before a request whose
  last check is older. A refusal or an unreachable directory ends every
  session of the account with the reason `directory_refused` (fail
  closed). While the check runs, a request gets
  `503 ldap_validation_in_progress` with `Retry-After: 1`.
- **Callback paths (invariant I-03).** `auth.PathOIDCLogin`
  (`/oidc/login`), `auth.PathOIDCCallback` (`/oidc/callback`),
  `auth.PathGitHubLogin` (`/auth/github/login`),
  `auth.PathGitHubCallback` (`/auth/github/callback`) and
  `auth.PathLDAPLogin` (`POST /login/ldap`) never change; a test of
  `internal/httpapi` checks that they are in the route catalog. The stored
  GitHub `redirect_uri` is kept byte for byte.
- **Tables.** Owners `authldap`, `authoidc`, `authgithub`:
  `authldap_identities` (E03), `authldap_revalidation` (E37),
  `authoidc_identities` (E05), `authgithub_identities` (E04),
  `authgithub_config` (E06, client secret sealed with
  `keyring.GitHubClientSecret`). The migration specification uses these
  names.
- **Test doubles.** `internal/auth/authtest`: `Provider` (a redirect
  provider whose codes the test issues, one use each), `Links` (in-memory
  links with the uniqueness rules), `Revalidator`.

### Step-up actions (identity and operation)

The names are those the Python release checks (`step_up_required`) and
the frontend sends; every action belongs to exactly one audience in
`internal/auth/stepup/audience.go` (administrator, own account, or any
account with a checked target), which a test enforces.

| Action | Used by |
|---|---|
| `user.manage` | `internal/accounts` (target `<user id>:<action>`) |
| `user.mfa_reset` | `internal/accounts` |
| `recovery.reset` | `internal/accounts` |
| `ldap.link` | `internal/auth/ldap` |
| `ldap.unlink` | `internal/auth/ldap` (target `<user id>:<identity id>`) |
| `oidc.link` | `internal/auth/oidc` |
| `oidc.unlink` | `internal/auth/oidc` (target `<user id>:<identity id>`) |
| `oidc.self_link` | `internal/auth/oidc` (own account) |
| `github.config` | `internal/auth/github` (target `global`) |
| `github.link` | `internal/auth/github` (own account) |
| `github.unlink` | `internal/auth/github` (own account) |
| `settings.update` | `internal/settings` (target `global`) |
| `audit.retention` | `internal/audit` (target `global`) |
| `backup.create` | `internal/backup` (target `new`) |
| `backup.cancel` | `internal/backup` |
| `backup.download` | `internal/backup` |
| `backup.upload` | `internal/backup` (target `upload`) |
| `backup.restore_prepare` | `internal/backup` |
| `backup.restore` | `internal/backup` |
| `operations.session.disconnect` | `internal/operations` (target: session reference) |
| `operations.connection.disconnect` | `internal/operations` (target: connection reference) |
| `operations.transfer.cancel` | `internal/operations` |
| `host_key.global_add` | `internal/ssh/hostkey` (target `global`) |
| `host_key.global_delete` | `internal/ssh/hostkey` |
| `server.operation` | `internal/hostops` (target: operation intent) |

The M2 plan's working names (`user.lock`, `identity.link`,
`backup.restore` with `secret.rotate`, …) are replaced by these. Secret
rotation is a CLI command only and has no step-up action.

### Error codes (operation)

| Code | HTTP status | Default message |
|---|---|---|
| `action_unconfirmed` | 503 | The action could not be confirmed. |
| `deployment_locked` | 409 | The setting is controlled by the deployment configuration. |
| `out_of_range` | 400 | A value is out of range. |
| `ldap_validation_in_progress` | 503 | Directory session validation is in progress. |

`out_of_range` carries `setting`, `min` and `max` as details;
`deployment_locked` carries `setting` and `policy`. The operations routes
answer a connection, session or transfer that is gone with
`404 {"code": "unavailable"}` as the Python release does; like the admin
step-up's `invalid_value`, `internal/operations` writes that answer itself.

New revocation reason: `directory_refused` (terminals end, as for a lock).
New keyring purposes: `github_client_secret` (Seal), `factor_bootstrap`
and `backup_download` (MAC). New store owners: `authgithub`, `authldap`,
`authoidc`, `backup`.

### Operation

- **Backup format** stays `webssh-go-backup` version 1
  (`internal/backup/backup.go`). Online backups snapshot the live database
  through `backup.Snapshotter` (`internal/store`, `VACUUM INTO`), write the
  archive with mode 0600 into `BACKUP_TEMP_DIR`, and are downloaded once
  with a token stored as its MAC (`keyring.BackupDownload`) after the
  `backup.download` step-up. `--without-secret-key` leaves out
  `data/secret_key` and the keyring material (D-08).
- **Restore** reads Go archives strictly (D-30: no absolute paths, no
  `..`, no links or devices, every member in the manifest) within
  `backup.Limits` (the `BACKUP_MAX_*` values and defaults of the Python
  release). Python backups (`python-v1`, `python-v2`) go through
  `backup.LegacyRestorer.RestoreLegacy`, implemented in
  `internal/migrate/legacy` with the steps of the one-time migration and
  connected in `cmd/webssh/wire_backup.go`; `internal/backup` never imports
  it.
- **States.** Operations use the Python statuses (`pending`, `running`,
  `uploading`, `verifying`, `verified`, `ready`, `downloading`,
  `restoring`, `failed`); `Active()` marks those that cannot be cancelled.
  A restore has `preparing`, `in_progress`, `succeeded`, `failed`,
  `rollback_failed`; the blocking ones keep the server in maintenance after
  a restart until it is finished (table `backup_restore`). A legacy
  `restore-status.json` is only read by the migration (A10).
- **Maintenance.** `backup.Maintenance` (`Enter(ctx, reason) (leave,
  error)`, `Active()`), provided by `cmd/webssh`: `/ready` answers 503,
  every other route `503 maintenance`, realtime connections close with
  4503 and new ones are refused. Reasons `restore`, `rotation`,
  `legacy_source_changed`; only one at a time (`busy` otherwise); the
  last one ends only with a restart.
- **Audit.** `internal/audit/export.go`: `MaxExportScan` 50,000 lines,
  `ExportFilter{From, To, Level, Query}`, `ExportMeta{Scanned, Truncated}`
  with `Completeness()` for `X-WebSSH-Audit-Completeness`, `Record` with
  the raw line so Python lines are exported byte for byte. Retention is
  the rotation's `backup_count` (1 to 90) and needs no job (the plan's
  retention job is not needed).
- **Instance operations.** `internal/operations/runtime.go` declares the
  sources of the operations view: `Connections` (realtime), `Sessions`
  (terminal), `Transfers`, `Jobs`, `Quotas`. References are
  `operations.ConnectionRef(id)` = hex `sha256("admin-connection:"+id)`
  and `operations.SessionRef(id)` = hex `sha256("admin-ssh:"+id)`, tested
  against Python vectors. Raw ids never reach the browser.
- **Integration switches** (C-ASET-05) are the existing
  `settings.App.RuntimeFeature(name)` with `FeatureStatus{Enabled, Saved,
  Source}`; `Source` keeps the Python values `compose` (locked by an
  explicit environment value), `admin` and `default`, and changes answer
  `409 deployment_locked` for a locked switch.
- **Support report.** `operations.SupportRequest` with the areas
  `general`, `ssh`, `files`, `sign_in`, `automation` and the optional
  reference `SMB-` plus 12 upper-case hex digits; anything else is
  `invalid_request` ("Invalid report options"). The report lists the
  features and readiness failures of `SupportFeatures` and
  `SupportReadinessFailures` and never reads logs, targets or account data.
- **Test doubles.** `internal/backup/backuptest`: `Maintenance` and
  `Restorer`.

### Wiring per area

`cmd/webssh/wire_areas.go` lists the areas of M2 in a fixed order; each
has its own file `wire_<area>.go` with a function `<area>Area()
extension`, and the package that builds the area edits only that file.
The extension hooks are `schemas`, `prepare` (optional dependencies before
the capabilities are built), `wire` (HTTP routes on `sys.edge.Mux()` and
realtime types with `sys.realtime.Mount`), `background` (periodic work on
`sys.background`, ending with its context) and `migrate` (the migration
steps of the entities the area takes over, after those of the release).
The wire files also hold the compile-time checks that existing providers
satisfy the area's consumer interfaces.

| Area | Package |
|---|---|
| `ldap` | ID1 |
| `oidc` | ID2 |
| `github` | ID3 |
| `accounts` | ID4 |
| `sshext` | NW1 |
| `gateway` | NW2 |
| `jobs` | RT1 |
| `terminal` | TM1 |
| `serverops` | HO1 |
| `discovery` | HO2 |
| `hostcontext` | HO3 |
| `files` | FS1 |
| `sftp` | FS2 |
| `smb` | FS3 |
| `credentials` | VA1 |
| `transfers` | TR1 |
| `commands` | CM1 |
| `automation` | AU1 |
| `schedules` | AU2 |
| `backup` | OP1 |
| `rotation` | OP2 |
| `operations` | OP3 |
| `platform` | PF1 |

A test checks that the files and the list agree.

### Route catalog by area

The 501 catalog of `internal/httpapi` is split by area:
`routes_areas.go` lists the areas, and each `routes_<area>.go` holds
`<area>Built` (routes with their access level) and `<area>Preview` (routes
that still answer 501). A package moves each route it builds from the
preview list to the built list of its own file. The areas are `ldap`
(ID1), `oidc` (ID2), `github` (ID3), `accounts` (ID4), `retired` (FE1:
`POST /api/totp/disable`, without a caller after D-13), `backup` (OP1),
`operations` (OP3), `hostcontext` (HO3), `discovery` (HO2), `serverops`
(HO1), `credentials` (VA1), `automation` (AU1), `schedules` (AU2) and
`transfers` (TR1). The test against the Flask route table is unchanged:
every Python route is built or a preview route, never both.

### Realtime shim by area

The name table of the shim is split into `static/js/realtime-shim-<area>.js`
(`hosts`, `keys`, `settings`, `notes`, `files`, `smb`, `commands`,
`insights`, `terminal-tools`). Each file registers
`{requests, refresh, unavailable, features}` on `WebSSHRealtimeAreas`;
`realtime-catalog.js` joins them in that order, and an event in two areas,
or both built and answered as unavailable, stops the load. A package that
builds an area adds its `requests` and removes its `unavailable` replies
and feature patterns. Only the Go workspace loads the files, after
`realtime-wire.js` and before `realtime-catalog.js`; the Python templates
load none of them. The split changes no behaviour (JS tests compare the
joined table with the M1 table).

New message types of M2 (section 4.10 of the plan: `files`, `transfer`,
`smb`, `commands`, `insights`, `inventory`, `herdr`, `gateway`,
`hostops.discovery`) are not fixed here; each is added to the catalog of
`internal/realtime/protocol` with its `Spec` by the package that builds
it, in a contract commit.

### End-to-end harness for M2

- `tests/e2e/go-suite.json` (formerly `tests/e2e/m1/go-subset.json`) lists
  the specs that must pass against Go; `tests/e2e/run-go-suite.js` runs
  them. Every excluded test has a `reason` and either the M2 package that
  unlocks it (`package`) or a capability of the build (`requires`); the
  runner refuses an entry without them.
- `serial: "e2e_admin"` marks specs that change stored settings of the
  shared seed account. With `--workers N` (N > 1) the other specs run in
  parallel and the marked ones afterwards on one worker.
- Seed parts the build skips are listed with their owner package in
  `internal/e2eseed/owners.go`; the package adds the applier with the
  entity and removes the row.
- Test hooks stay in the build tag `e2e` and the type namespace `e2e.`
  (M1 contracts, "End-to-end harness").
