# Authentication Overview

WebSSH supports local credentials plus optional external identity methods. All
methods resolve to an existing WebSSH `User`; identity providers do not grant
unbounded access to application state.

## Method comparison

| Method | Default | Identity binding | Suitable for |
|---|---:|---|---|
| Local password | Enabled | WebSSH username | Bootstrap, break-glass, ordinary local accounts |
| Passkey/WebAuthn | Disabled | Credential owned by a local account | Phishing-resistant local sign-in |
| Recovery code | Enabled | One-time code owned by a local account | Loss of password or passkey |
| OIDC | Disabled | Exact issuer and subject linked by an admin | Existing OpenID Provider |
| LDAP/Active Directory | Disabled | Stable directory ID linked by an admin | Lab or organization directory authentication |

## Common controls

- Flask-Login manages browser authentication.
- Forms use Flask-WTF CSRF protection.
- Unknown-user password checks perform dummy bcrypt work.
- Login and reauthentication paths are rate-limited.
- Session cookies are `HttpOnly` and `SameSite=Lax`; production requires the
  `Secure` flag.
- Lock, deletion, logout, and failed LDAP revalidation revoke tracked live
  resources.
- Authenticated Socket.IO events use `socket_login_required` and resource
  operations add ownership checks.

## Local passwords

WebSSH passwords are bcrypt hashes with generated salts. They are separate from
SSH target passwords. Target passwords are used for connection establishment
and are not written into profiles, the database, or audit logs.

Keep one local administrator even when external identity is enabled. An
external provider outage should not remove the operator's only recovery path.

## Passkeys

Passkeys are username-less discoverable WebAuthn credentials. The browser and
server must agree on the exact RP ID and origin. HTTPS is required outside the
localhost homelab exception.

Server-side challenges are bound to the browser session, one use only, and
expire after five minutes.

See [Passkeys and Recovery Codes](Passkeys-and-Recovery-Codes).

## Recovery codes

Recovery codes are one-time alternatives for local accounts. WebSSH stores only
domain-separated hashes and performs fixed expensive verification work. A new
set invalidates the old set.

Store the plaintext set offline; it cannot be displayed again.

## OpenID Connect

OIDC uses the authorization-code flow with PKCE, nonce, state, and a
session-bound one-use login record. An administrator must link the exact issuer
and subject to a local account. Optional subject and email-domain rules are
additional admission filters, not identity keys.

See [OpenID Connect](OpenID-Connect).

## LDAP and Active Directory

LDAP uses mandatory certificate-verified StartTLS or LDAPS. A service account
searches for exactly one entry, then WebSSH binds with the submitted user
password. The password is not stored.

An administrator links the directory's stable ID to an existing non-admin
account. Linked accounts become exclusively LDAP-managed and are periodically
revalidated fail-closed.

See [LDAP and Active Directory](LDAP-and-Active-Directory).

## Login-mode separation

The login UI presents optional identity methods as deliberate modes. A user who
chooses LDAP enters a dedicated LDAP form with a clear way back instead of
mixing directory fields into the local login form.

This separation matters operationally: local, OIDC, recovery, passkey, and LDAP
flows have different failure and recovery semantics.

## Session revocation

Account revocation is broader than clearing a cookie. WebSSH attempts to cancel
transfers, disconnect Socket.IO sessions, close SSH sessions, close pooled
connections, and remove persisted session metadata.

LDAP adds periodic directory revalidation. A missing or changed identity,
directory exclusion, TLS failure, outage, or disabled feature invalidates the
managed user's access.

## Recommended rollout order

1. Deploy WebSSH with a local administrator.
2. Test local login and recovery codes.
3. Put the instance behind its final HTTPS origin.
4. Enable and test passkeys if required.
5. Configure one external provider.
6. Link one non-admin pilot account.
7. Test provider outage and rollback behavior.
8. Expand only after the break-glass path is verified.
