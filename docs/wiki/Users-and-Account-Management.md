# Users and Account Management

WebSSH is multi-user. Each account has separate profiles, commands, jump hosts,
settings, notes, SSH keys, host trust, live sessions, and transfer ownership.

## Roles

### Standard user

A standard user can manage their own SSH/SFTP data and security factors. They
cannot access the Admin Panel or another user's state.

### Administrator

An administrator can:

- create users;
- lock and unlock accounts;
- promote or demote administrators;
- delete users;
- configure registration;
- view and export bounded audit data;
- manage global host trust;
- generate replacement recovery-code sets after reauthentication;
- link and unlink OIDC identities;
- link and unlink LDAP identities when LDAP is enabled;
- create and restore native backups.

Administrators remain subject to authentication, CSRF, rate limits, target
confirmation, and reauthentication requirements.

## First administrator

### Homelab browser bootstrap

On a fresh homelab database, `BOOTSTRAP_REGISTRATION_ENABLED` defaults to true.
Exactly the first browser-created account becomes administrator, and the
bootstrap registration path closes immediately afterward.

Do not expose an empty instance to an untrusted network. If another person
claims the first account, they control the deployment.

### CLI bootstrap

Production disables browser bootstrap. Create or promote an administrator:

```bash
flask --app start:app create-admin --username admin
```

Docker Compose:

```bash
docker compose exec webssh \
  /app/entrypoint.sh flask --app start:app create-admin --username admin
```

For automation, `--password-file` accepts a private regular non-symlink file.
The command does not print or audit the password.

`ADMIN_USERS` is a compatibility option that promotes listed existing users on
startup. Prefer the explicit CLI for normal administration.

## Registration modes

Two settings serve different purposes:

- `BOOTSTRAP_REGISTRATION_ENABLED` allows one first browser-created
  administrator only while the database has no users.
- `REGISTRATION_ENABLED` controls ordinary self-registration for additional
  standard users.

The homelab Admin Panel can store the ordinary registration toggle. A stored
setting takes precedence over the initial environment value. Production keeps
registration closed even if an administrator attempts to reopen it from the UI.

## Creating users

Use **Administration → Users** to create a standard account. Generate a unique
initial password, deliver it over a separate trusted channel, and require the
user to change it.

Passwords are bcrypt hashes at rest. New or changed passwords are limited to
72 bytes after UTF-8 encoding because of bcrypt's input boundary.

## Locking an account

Locking prevents new HTTP and Socket.IO authorization. WebSSH also revokes the
account's tracked resources:

- active transfers;
- Socket.IO sessions;
- live SSH sessions;
- pooled temporary SSH/SFTP connections;
- persisted socket and SSH session metadata.

Unlocking permits future authentication but does not restore terminated live
connections.

## Deleting an account

Deletion first revokes live access. The database row is deleted, while the
active per-user directory is moved atomically to:

```text
DATA_DIR/deleted_users/user_<id>_<uuid>
```

This quarantine prevents a future numeric user ID from inheriting the deleted
account's files. It is retention, not secure erasure. Operators must define a
review and secure-disposal policy for `deleted_users`.

If database deletion fails, WebSSH attempts to move the quarantined directory
back into the active namespace.

## External identity ownership

External identity is always linked to an existing local WebSSH account by an
administrator.

- OIDC uses the provider's stable issuer and subject. Email alone is never an
  identity key.
- LDAP uses the configured provider ID and stable directory attribute such as
  `entryUUID` or `objectGUID`.
- OIDC and LDAP mappings cannot be combined on one LDAP-managed account.
- LDAP-managed accounts cannot be administrators.
- LDAP linking removes local and alternative login factors; unlinking requires
  a fresh local password.

Keep a separate local break-glass administrator before enabling external
identity.

## Password changes and logout

Local users can change their password through `/change-password`. Explicit
logout is a POST action and revokes tracked Socket.IO, SSH, and temporary SFTP
connections instead of only deleting the browser cookie.

LDAP-managed users authenticate exclusively against the directory and cannot
use the local password-change, passkey, recovery-code, or OIDC flows.

## Account recovery

Local accounts can use one-time recovery codes when enabled. Administrators can
replace a user's recovery set only after reauthentication and exact target
confirmation. Recovery codes are shown once and stored only as hashes.

## Operational checklist

- Maintain at least two tested administrative recovery paths where practical.
- Review administrator membership regularly.
- Lock an account immediately when access should stop.
- Treat quarantined user files as sensitive retained data.
- Export only the bounded audit data required for an investigation.
- Test external identity with a non-admin pilot before migrating more users.

## Related pages

- [Authentication Overview](Authentication-Overview)
- [LDAP and Active Directory](LDAP-and-Active-Directory)
- [OpenID Connect](OpenID-Connect)
- [Passkeys and Recovery Codes](Passkeys-and-Recovery-Codes)
