# WebSSH 3

This document describes the version 3 candidate. It does not announce a published
release; existing release-history entries remain the record of shipped versions.

## Start where you work

Under **Settings > Preferences**, choose **Overview** or **Workspaces** as your
start page. The preference belongs to your account and survives sign-out.
Overview remains the default. Direct links, such as Automation, keep their target.
Choose the dashboard or the classic overview independently in the same settings.

The dashboard combines infrastructure, SSH routes and automation results. Route
counts open the corresponding hosts in the expanded map. Drag nodes there to
arrange the topology; arrangements are stored per account in this browser.
Wide and narrow layouts are saved separately. The compact map uses readable
route summaries instead of shrinking the complete topology into unreadable text.
Clearing browser storage removes these local arrangements. The map describes
saved configuration, not a live availability probe.

## Reusable operations

Automation combines editable templates, your command library and command sets.
Review target hosts before immediate execution, or create a timezone-aware
schedule. Run history includes bounded stdout/stderr, exit status and duration.
Unknown outcomes remain explicitly unknown, rather than reported as success.
Automation is administrator-controlled and disabled by default. Direct SSH is
supported; jump-host, gateway and Tailscale automation routes are not supported.
See [Automation](automation.md) for prerequisites, sudo behavior, output limits,
schedule invalidation and cancellation boundaries.

## Credentials and upgrades

Optional saved passwords are encrypted per account and can be assigned to saved
hosts, jump hosts and supported file sources. A host uses one saved password;
replacement changes its assignment. Existing sessions are not reauthenticated.

Back up application data before upgrading and preserve the instance secret.
Application backup exports deliberately omit stored passwords, legacy vaults
and SSH private keys. These must be re-provisioned after restore from a separate
trusted source. Backup archives still contain sensitive account/configuration
data and may contain the instance secret; protect them. Internal administrative
rollback snapshots have different contents and are not portable user exports.
See [Credentials](credentials.md) and the [backup guide](wiki/Backup-Restore-and-Secret-Rotation.md).

## Media

The README and product tour use browser captures of the version 3 candidate with
prepared example data, never a user's servers or credentials. The theme GIF
shows all eleven themes. The silent video and slide gallery are visual tours;
they do not claim successful operations on real servers. The previous narrated
version 2 video is retained only as clearly labeled historical material.

## Release validation

Version 3 remains a candidate until the final revision passes the release gates.
The release workflow derives container tags `3.0.0` and `3.0` from the Git tag
`v3.0.0`; creating or publishing that tag is a separate release action.

Before publication:

- Run CI and native AMD64/ARM64 image acceptance against the final revision.
  Emulated ARM64 checks do not replace native acceptance.
- Rebuild and scan the final image after Debian security updates. Outstanding
  SQLite findings are not resolved by restore hardening alone. Imported backup
  databases are parsed during verification, including upload verification;
  administrator authorization does not make an external archive trustworthy.
- Recheck backup, restore and rollback against that image. Exported credentials
  remain excluded; internal rollback snapshots must preserve recovery state.
- Assess all remaining image findings. A SQLite-specific assessment is not a
  security clearance for other packages. Any release with unresolved findings
  requires an explicit, documented maintainer risk decision.

Checksums establish archive integrity, not the provenance of an imported backup.
Use backups from controlled, trusted sources. Do not interpret successful
validation as proof that an arbitrary SQLite database is safe to parse.


## First-login tour

An optional eight-step tour introduces the overview, hosts, workspaces, files, commands and automation after login. Back and Next move between the actual application views without connecting to hosts or executing commands. Every account sees the version 3 tour once after login. Skipping closes it and is remembered for the account; completing it requires checking the acknowledgement on step eight. Reopen it at any time from the account menu with Product tour.

The final steps show an allowlisted view of effective deployment flags and administrator feature policies. Authentication features also require their readiness and administrator gates. No environment secrets, host paths or Compose contents are exposed. Process root status is not a statement about Docker privileges, host mounts or remote SSH/sudo permissions. Documentation links open the product Wiki; administration links are shown only to administrators when the admin panel is available.


## Configuration ownership during upgrades

Version 3 manages file permission changes, server operations, tmux availability,
the tmux preselection and automation under **Administration → Integrations**.
Existing Compose and `.env` files keep working unchanged for all of 3.x.

Rules:

1. A non-empty environment value for one of these switches wins and locks the
   Admin switch. Settings names the variable, the effective value and the saved
   Admin value. An empty value (`X=` or `X=${X:-}`) counts as not set.
2. On the first start with such a value and no saved Admin value, the value is
   stored once. Removing the line later keeps the same behavior and unlocks the
   switch.
3. `REGISTRATION_ENABLED` stays an initial value, as in 2.x: a choice saved in
   Administration wins. The production profile always disables registration.
4. Product defaults: tmux available but not preselected; file permissions,
   server operations, automation and saved passwords off. Saved passwords stay
   on when a 2.x vault exists.

| Switch | New installation (new Compose) | Existing, old Compose unchanged | Existing, new Compose before the first 3.0 start | Existing, new Compose after the first 3.0 start |
|---|---|---|---|---|
| tmux available | on, editable | on, locked by Compose | on (default), editable | on (stored), editable |
| tmux preselected | off, editable | off, locked by Compose | off (default), editable | off (stored), editable |
| File permissions | off, editable | as in the Compose; locked if set | off (default) | as before (stored), editable |
| Server operations | off, editable | as in the Compose; locked if set | off (default) | as before (stored), editable |
| Registration | off, editable | as in 2.x, editable | as in 2.x, editable | as in 2.x, editable |
| Automation | off, editable | off, editable | off, editable | off, editable |

Behavior is identical to 2.x in every column, with one exception: if file
permissions or server operations were explicitly enabled in the old Compose
and that file is replaced before the first 3.0 start, the value cannot be
recovered and the feature is off. Carry those lines over, or enable the
features in Administration after the upgrade.

Changing an environment value later wins again while it is set; the stored
Admin value is shown and applies once the line is removed. Changing the
effective automation value between restarts revokes approved schedules.
A rollback to 2.x ignores the stored Admin values and follows its environment.

Authentication capabilities retain separate readiness and activation checks.
TOTP capability is available by default; Admin activation remains required.
