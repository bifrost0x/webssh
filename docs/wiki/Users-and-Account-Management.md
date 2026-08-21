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
confirmation, and action-bound Step-up requirements.

## Administrator Step-up

Sensitive mutations require a one-use grant for the exact action and target.
Examples include user creation and role/lock/delete changes, MFA reset, identity
linking, authentication-feature policy, audit retention, global host trust, and
backup/restore operations.

- A local administrator without enabled MFA confirms the current password.
- An MFA-enabled administrator uses Passkey or TOTP.
- Sufficiently recent strong OIDC assurance may be reused; otherwise provider
  reauthentication is required.

The grant is bound to the current server-side authentication session, expires
after five minutes, and is consumed before route execution. It cannot authorize
another user or operation and is never persisted in browser storage.

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

External identity resolves to a local WebSSH account. OIDC always requires an
administrator-created link. LDAP uses the same controlled link by default;
explicit `LDAP_AUTO_PROVISION=true` can instead create a non-admin account only
after successful directory authentication and only when no local username or
stable identity collides.

- OIDC uses the provider's stable issuer and subject. Email alone is never an
  identity key.
- LDAP uses the configured provider ID and stable directory attribute such as
  `entryUUID` or `objectGUID`.
- OIDC and LDAP mappings cannot be combined on one LDAP-managed account.
- LDAP-managed accounts cannot be administrators.
- LDAP linking removes the dormant local password and incompatible OIDC mapping;
  Passkey/TOTP factors remain attached to the WebSSH account and can protect the
  LDAP primary login. Unlinking requires a fresh local password.

Keep a separate local break-glass administrator before enabling external
identity.

## Password changes and logout

Local users can change their password through `/change-password`. Explicit
logout is a POST action and revokes tracked Socket.IO, SSH, and temporary SFTP
connections instead of only deleting the browser cookie.

LDAP-managed users authenticate their primary credential exclusively against
the directory and cannot use local password-change or OIDC. After recent LDAP
verification they can enroll Passkey or TOTP factors and use Recovery Codes for
the second factor.

## Optional MFA

Passkeys, authenticator apps, and Recovery remain optional per account. Admin
activation makes a deployment-ready feature available; it does not force every
user to enroll. Accounts without enabled MFA keep their existing password,
LDAP, or configured OIDC sign-in. Once enabled on an account, a basic primary
login continues to an available Passkey, TOTP, or Recovery method.

## Account recovery

MFA-enabled accounts can use one-time Recovery Codes only after successful
password or LDAP primary verification. The resulting session remains restricted
to factor replacement or explicit MFA disable. Administrators can replace a
user's recovery set only after Step-up and exact target confirmation. Codes are
shown once and stored only as hashes.

An explicit administrator MFA reset deletes all target Passkeys, TOTP state,
WebAuthn challenges, and Recovery Codes, disables MFA, advances the target's
authentication generation, and revokes that account's active WebSSH/SSH access.
It is distinct from changing a feature policy: enabling or disabling a feature
does not forcibly kill existing sessions, which continue until their normal
configured lifetime.

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
