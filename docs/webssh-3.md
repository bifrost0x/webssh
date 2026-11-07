# WebSSH 3

This document describes the version 3 candidate. It does not announce a published
release; existing release-history entries remain the record of shipped versions.

## Start where you work

Under **Settings > Preferences**, choose **Overview** or **Workspaces** as your
start page. The preference belongs to your account and survives sign-out.
Overview remains the default. Direct links, such as Automation, keep their target.
Choose the dashboard or the classic overview independently in the same settings.

The dashboard shows the state of your saved hosts, open sessions and
automation at a glance:

- Status tiles for host readiness, open sessions, automation success over the
  last 14 days and reachability.
- A route summary from WebSSH through direct routes and jump hosts to each host.
  **Open map** shows the complete topology; drag nodes there to arrange it.
  Arrangements are stored per account in this browser, separately for wide and
  narrow layouts, and are lost when browser storage is cleared.
- Host cards with platform, route and a readiness badge. Readiness comes from
  stored configuration only: unknown host keys, missing keys, changed saved
  passwords and missing jump hosts. Loading it never opens an SSH connection.
- A list of items that need attention, an automation chart with the next
  scheduled run, a platform breakdown and recent activity.

Select **Customize** to arrange the dashboard: drag a panel by its handle,
resize it from its corner, change its width with the panel buttons, hide it or
show it again from the edit bar. The arrow keys move a focused panel handle.
**Reset layout** restores the default. The layout is stored per account; on
narrow screens panels stack in the same order and follow their content height.

Items under **Needs attention** can be dismissed one by one or all at once. A
dismissed item stays hidden for this account until the situation changes, for
example a new failed run or another host without a verified host key. **Show
again** brings dismissed items back.

Press <kbd>/</kbd> to search hosts, <kbd>Enter</kbd> to connect to the first
match and the arrow keys to move between hosts.

### Reachability checks

Under **Settings > Preferences > Host reachability on Overview** each account chooses how
the dashboard checks whether hosts answer:

| Mode | Behavior |
| --- | --- |
| When I ask (default) | Checks run only when you select **Check now**. |
| Automatically while Overview is open | Checks run when the dashboard opens and every five minutes while it is visible. |
| Never | No checks are made. |

A check opens and immediately closes a TCP connection to the SSH port. It does
not start an SSH handshake and sends no credentials. Hosts behind a jump host
are reported through the jump host, which is the only system WebSSH contacts
directly. Checks follow the same network policy as SSH connections
(`BLOCK_INTERNAL_SSH`, `SSH_ALLOWED_INTERNAL_NETWORKS`); blocked destinations
are reported as blocked, not probed. A check covers at most 50 hosts, results
are reused for 60 seconds, and each account is rate limited. The last result
stays visible for up to 30 minutes after leaving or reloading the overview, as
long as the saved hosts are unchanged; showing it does not contact any host.

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
2. Until an administrator changes the switch, the stored value follows the
   last explicit environment value. Removing the line later keeps the behavior
   the operator set last and unlocks the switch; it never revives an older
   value.
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

An administrator's own choice is kept: a later environment value wins while
it is set, and the Admin choice applies again once the line is removed.
Without a value in the environment, an administrator can enable these
features in the web interface (with reauthentication); set the variable to
`false` to keep a feature off for good. Changing the effective automation
value between restarts revokes approved schedules.

Installations started without the example Compose (plain `docker run` or a
source install whose `.env` lacks `TMUX_ENABLED`) now offer tmux by default;
it stays unselected until a user enables it for a host or connection.
A rollback to 2.x ignores the stored Admin values and follows its environment.

Authentication capabilities retain separate readiness and activation checks.
TOTP capability is available by default; Admin activation remains required.
