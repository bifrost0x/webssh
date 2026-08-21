# Passkeys and Recovery Codes

Passkeys and recovery codes strengthen local account authentication. LDAP-
managed accounts cannot use either method because their directory identity is
exclusive.

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

## Enroll a passkey

1. Sign in with the local password or a recovery code.
2. Open **Security**.
3. Start passkey enrollment.
4. Complete the authenticator prompt.
5. Give the credential a recognizable name where supported.
6. Sign out and test passkey login before depending on it.

Enroll more than one authenticator when losing one device would otherwise lock
out the account.

## Legacy passkeys

Older WebSSH releases could create non-discoverable credentials. They cannot be
used by the current username-less flow.

Sign in with a local password or recovery code, open **Security**, and choose
**Replace legacy passkey**. After current-password confirmation, WebSSH permits
the same authenticator to create a discoverable replacement. Test the new
credential before deleting the old record.

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

## Recover an account

Use the recovery option on the login page with the WebSSH username and one
unused code. After login, replace the lost password or passkey and generate a
new recovery set.

## Administrator replacement

An administrator can generate a replacement set for a target account only
after password reauthentication and exact target confirmation. Deliver the new
set through a trusted channel. The administrator cannot retrieve old codes.

## Avoid lockout

- Keep at least one local break-glass administrator.
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

Codes are normalized for spaces and case, but are one use only. Confirm the
username, use an unused code from the latest set, and check that the account is
not LDAP-managed or locked.

## Related pages

- [Authentication Overview](Authentication-Overview)
- [Users and Account Management](Users-and-Account-Management)
- [Production Deployment](Production-Deployment)
