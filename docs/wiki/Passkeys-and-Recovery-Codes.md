# Passkeys, Authenticator Apps, and Recovery Codes

Passkeys and authenticator apps are optional account factors. Recovery Codes
provide second-factor recovery after a valid primary login. LDAP-managed users
may enroll these local WebSSH factors after recent directory verification; the
LDAP password remains exclusively directory-managed and is never stored.

## Capability and activation

The operator first allows each feature in Compose/environment, then an
administrator activates the ready capability under **Admin → Settings →
Authentication features**. An Admin toggle cannot override
`WEBAUTHN_ENABLED=false`, `TOTP_ENABLED=false`, or
`RECOVERY_CODES_ENABLED=false`. Users who do not enroll and enable MFA retain
their existing login.

## Passkey prerequisites

Passkeys are disabled by default. Configure the exact browser-visible origin:

```bash
WEBAUTHN_ENABLED=true
WEBAUTHN_RP_ID=ssh.example.com
WEBAUTHN_RP_NAME=WebSSH
WEBAUTHN_ORIGIN=https://ssh.example.com
MAX_WEBAUTHN_JSON_SIZE=65536
```

- RP ID is the domain only, without scheme or port.
- Origin includes scheme and any non-default port.
- HTTPS is required outside the `localhost` homelab exception.
- Reverse-proxy and public-origin settings must agree.

## Passkey security properties

- Username-less authentication uses discoverable credentials.
- User verification is required by the ceremony.
- Challenges are stored server-side and bound to the browser session.
- Challenges are one use only and expire after five minutes.
- Registration and authentication payloads are capped at 64 KiB.
- Credential inventory and deletion require authenticated ownership.

## Direct Passkey login and Passkey MFA

Passkeys can be used in two distinct ways:

- **Direct Passkey login** selects **Sign in with Passkey** on the login page.
  It does not ask for the account password and creates a phishing-resistant
  session after the authenticator verifies the user.
- **Passkey MFA after primary login** first verifies the local password, LDAP,
  or another configured primary method, then requires an enrolled Passkey,
  authenticator app, or Recovery Code.

Merely enrolling a Passkey does not make the account password path require a
second factor. After adding and testing a Passkey, choose **Require Passkey MFA
for password sign-in** in **Security**. WebSSH requires recent action-bound
Step-up, enables account MFA atomically, and returns a new ten-code Recovery set
once. Store those codes before leaving the page.

When account MFA is enabled, an enrolled Passkey is one eligible second factor;
WebSSH does not require the same specific Passkey on every login. Direct Passkey
login remains available and already provides phishing-resistant assurance.

The Admin authentication-feature switches are deployment and availability
controls, not organization-wide enrollment policy. This release does not let
an administrator force MFA or Passkey enrollment for every account. Such a
policy needs an enrollment grace period, recovery and break-glass rules, and a
safe treatment for service or directory-managed accounts to avoid mass
lockout.

## Enroll a passkey

1. Sign in with the local password or LDAP. If MFA is already enabled, complete
   another available factor or Recovery after that primary step.
2. Open **Security**.
3. Start passkey enrollment.
4. Complete the authenticator prompt.
5. Give the credential a recognizable name where supported.
6. Sign out and test passkey login before depending on it.
7. If password or directory sign-in must not remain a single-factor fallback,
   return to **Security** and enable Passkey MFA.

Enroll more than one authenticator when losing one device would otherwise lock
out the account.

## Legacy passkeys

Older WebSSH releases could create non-discoverable credentials. They cannot be
used by the current username-less flow.

Complete primary login and another available factor, or use Recovery after
primary verification, open **Security**, and choose **Replace legacy passkey**.
After recent primary authentication, WebSSH permits the same authenticator to
create a discoverable replacement. Test the new credential before deleting the
old record.

## Authenticator apps (TOTP)

Set the deployment ceiling and restart/recreate WebSSH:

```bash
TOTP_ENABLED=true
```

Then activate TOTP in the Admin Panel. On **Security**, the user chooses **Add
authenticator**, confirms the recent primary credential when required, scans
the locally rendered QR code (or enters the setup key), and verifies one
six-digit code. The enrollment expires after five minutes. The secret is
encrypted per user with key material derived from `SECRET_KEY`, is never stored
in browser local/session storage, and accepted time steps cannot be replayed.

First activation enables MFA and generates a one-time Recovery set. Store it
before leaving the page. Enabling TOTP remains voluntary; the Admin feature
toggle makes enrollment available but does not enroll or force users.

## Recovery codes

Recovery codes are enabled by default and can be disabled with:

```bash
RECOVERY_CODES_ENABLED=false
```

`MAX_RECOVERY_JSON_SIZE` defaults to 4096 bytes.

WebSSH generates ten codes by default and supports a bounded set of 1-20. The
plaintext codes are returned once. Only domain-separated SHA-256 hashes are
stored, and verification performs fixed expensive work to reduce obvious timing
differences.

## Generate and store codes

1. Open **Security** while signed in.
2. Generate a recovery set.
3. Save it in an encrypted password manager or another offline secure location.
4. Confirm the storage can be accessed without the WebSSH instance.

Generating a new set replaces the previous set. Each code is consumed once.

## Recover the second factor

First complete the account's local-password or LDAP primary login. When WebSSH
asks for MFA, select Recovery and enter one unused code. OIDC basic assurance
can likewise lead to the local factor selection when the linked account enabled
MFA.

The code creates a restricted recovery session, not a normal login. Only
`/security`, Passkey/TOTP replacement, explicit MFA disable, logout, and the
required static resources are available. Normal terminal, SFTP, Admin, and API
access remains blocked. Enrolling and verifying a replacement factor clears
the restriction; explicit MFA disable requires typing the account name.

## Administrator replacement

An administrator can generate a replacement set for a target account only
after action-bound Step-up and exact target confirmation. Deliver the new set
through a trusted channel. The administrator cannot retrieve old codes.

An administrator can also perform an explicit MFA reset. This deletes the
target's Passkeys, TOTP authenticators/enrollments, WebAuthn challenges, and
Recovery Codes, disables MFA, increments the account authentication generation,
and revokes that target's WebSSH/SSH sessions. The response never returns factor
secrets. Use this only as a deliberate account-recovery action.

## Avoid lockout

- Keep at least one local break-glass administrator with two tested factors.
- Test passkey sign-in after enrollment and origin changes.
- Keep recovery codes separate from the WebSSH host and data volume.
- Do not remove the last working factor until its replacement is tested.
- After a suspected code disclosure, generate a new set immediately.

## Troubleshooting

### The browser rejects the RP ID or origin

Use the exact public hostname. Do not include a scheme or port in
`WEBAUTHN_RP_ID`. Include the scheme and port in `WEBAUTHN_ORIGIN`. Confirm the
reverse proxy preserves the public host and HTTPS scheme.

### A passkey works on localhost but not production

Production has a different origin and usually a different RP ID. Reconfigure
the exact public values and enroll credentials for that relying party.

### A recovery code fails

Codes are normalized for spaces and case, but are one use only. Complete the
primary login, use an unused code from the latest set, and check that the
account is not locked and that Recovery is effectively active.

## Related pages

- [Authentication Overview](Authentication-Overview)
- [Users and Account Management](Users-and-Account-Management)
- [Production Deployment](Production-Deployment)
