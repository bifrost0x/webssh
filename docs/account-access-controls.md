# Account access controls

## Browser logins

Settings → Security overview lists this account's active server-side browser
logins, their authentication methods, start and expiry times, and the current
login. The management references shown to the browser are separate from the
credentials used to authenticate; session cookies and authentication hashes
are not returned.

**Revoke login** ends one other browser login. **Revoke all other logins** keeps
the current login. Use the existing Sign out action to end the current login.
Expired logins are omitted. Recovery sessions cannot manage other logins before
repairing their authentication factors.

Revocation removes the selected authentication records and associated step-up
state. Existing cookies, including Remember me, cannot recreate them. Attached
Socket.IO connections are disconnected, and their transfers, permission jobs
and connection attempts are cancelled. Login-bound credential access, manual
automation and discovery are revoked. Ongoing HTTP server-operation channels
recheck their captured authentication record and stop when it is revoked.
Transfer creation and socket admission are serialized against revocation so
an already-admitted browser cannot create new resources after the cancellation.

SSH/tmux sessions belong to the account and remain available to its other valid
logins. Scheduled automation is also account-owned and is not disabled by
revoking a browser. Already-issued remote commands are not rolled back and may
continue on the remote system. Interrupted transfers can leave partial files.
If live-resource cleanup fails, the login is still revoked and the UI reports
that some resources could not be closed; an operator should investigate.

## Disabling authentication features

Before disabling an active Passkey, TOTP, OIDC, LDAP or recovery-code feature,
the administrator sees affected account and administrator counts, primary-path
loss and local MFA-factor loss. Expand the details to identify affected accounts
and their remaining configured primary, factor and recovery paths. Locked
accounts are listed but omitted from remaining-path totals.

This is a configuration inspection, not a sign-in test. A stored local password
does not prove that its owner knows it. A configured provider does not prove
availability or external MFA assurance. Recovery codes permit restricted repair,
not a substitute unrestricted primary login. Test an alternative login before
disabling the current method.

The approval expires after five minutes and is bound to the feature, approving
administrator, browser login and account/factor configuration. Saving rechecks
that configuration in the same SQLite write transaction as the feature change.
If it changed, review the updated impact and authenticate again. Existing
deployment/readiness limits and action-bound step-up remain required.

Disabling a feature affects new logins and factor ceremonies. It does not
terminate existing browser, SSH or tmux sessions.

## Account deletion and retained files

The deletion confirmation names the selected account. Deletion revokes its
access and removes its database account. Its local user files are moved out of
the active user namespace into `DATA_DIR/deleted_users/user_<id>_<random>/`.
This is quarantine, not secure erasure, and no automatic cleanup is performed.

For later operator cleanup:

1. Identify the actual persistent data directory or mounted data volume used by
   this installation. Match the retained directory to the intended deleted
   account; inspect its contents and applicable retention requirements.
2. Decide whether an offline archive is required. Existing backups and separate
   archives have their own retention lifecycle and are not erased by account
   deletion or quarantine cleanup.
3. During a controlled maintenance window, explicitly remove only the verified
   quarantine directory using the operating system or volume-management tools.
   Verify the resolved path remains below `DATA_DIR/deleted_users/`. Do not remove
   the active `users/` directory, the database, or the complete data volume.

The application deliberately provides no automatic purge or browser action for
this irreversible operator step.
