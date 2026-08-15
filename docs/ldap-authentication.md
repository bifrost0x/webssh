# Optional LDAP and Active Directory authentication

LDAP authentication is optional and disabled by default. The regular
`docker-compose.yml` creates no LDAP volume, mount, or helper. Opting in uses
the provided `docker-compose.ldap.yml` overlay with the same WebSSH image; no
`.env` file or hand-written secret mount is required.

## Security model

- `LDAP_ENABLED=false` registers no LDAP routes, starts no LDAP job, reads no
  LDAP file, and makes no directory connection.
- `ldap://` always performs StartTLS before any bind. `ldaps://` starts with
  TLS. Plain LDAP authentication and disabled certificate verification are not
  supported.
- A least-privilege service account performs read-only user searches. The
  submitted user password is used only for the final bind and is never stored.
- Directory usernames are escaped as RFC 4515 filter values. Searches are
  subtree-scoped, limited to two results, and must resolve to exactly one entry.
- By default, an administrator explicitly links a directory identity to an
  existing local WebSSH user. Optional auto-provisioning still requires a
  successful password bind and never trusts a username by itself.
- The stable `entryUUID` (OpenLDAP) or `objectGUID` (Active Directory) is the
  identity key. A renamed DN can be updated after successful authentication
  without changing account ownership.
- LDAP users cannot be administrators and cannot fall back to local passwords,
  passkeys, recovery codes, or OIDC. Keep at least one unlinked local
  break-glass administrator.
- `LDAP_AUTO_PROVISION=true` creates a non-admin LDAP-managed account only
  after the first successful directory sign-in. It requires an active local
  break-glass administrator and never attaches LDAP to an existing local
  username. Case-insensitive collisions, control characters, and names longer
  than 80 characters are rejected without truncation.
- Linking destroys the user's dormant local password and all alternative local
  login factors. Unlinking requires a fresh local password.
- LDAP sessions are revalidated every five minutes by default. A disabled
  feature, directory outage, missing user, changed stable ID, locked account
  excluded by the configured filter, or certificate failure revokes the user's
  browser, Socket.IO, SSH, transfer, and pooled-connection access.

## Information you need from the directory administrator

Collect these values before activation:

1. An LDAP server DNS name whose TLS certificate matches that name.
2. Whether to use `ldap://host:389` with StartTLS or `ldaps://host:636`.
3. The user search base DN.
4. A read-only bind account DN and its password. It needs only enough access to
   search the configured base and read the stable ID attribute.
5. A PEM CA bundle containing the issuing root and any required intermediates.
6. A user filter containing exactly one literal `{username}` placeholder.
7. A stable unique-ID attribute (`entryUUID` or `objectGUID`).

DNS and system time must work inside the WebSSH container. Do not use an IP
address when the server certificate contains only a DNS name.

## Configure the LDAP Compose overlay

Edit `docker-compose.ldap.yml`. Selecting this overlay enables LDAP, so fill
every empty directory setting before starting WebSSH. The secret helper can be
run first without starting the WebSSH service. Always use base and LDAP Compose
files from the same WebSSH release.

### Active Directory example

```yaml
LDAP_ENABLED: "true"
LDAP_AUTO_PROVISION: "false"
LDAP_PROVIDER_ID: corp-ad
LDAP_URL: ldaps://dc01.ad.example.com:636
LDAP_BASE_DN: OU=People,DC=ad,DC=example,DC=com
LDAP_BIND_DN: CN=svc-webssh,OU=Service Accounts,DC=ad,DC=example,DC=com
LDAP_USER_FILTER: "(&(objectCategory=person)(objectClass=user)(sAMAccountName={username})(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
LDAP_UNIQUE_ID_ATTRIBUTE: objectGUID
```

The final filter clause excludes disabled AD accounts. If the organization has
a dedicated WebSSH access group, add a directory-approved `memberOf` clause.
Nested group semantics vary and must be validated by the AD administrator.

### Generic OpenLDAP example

```yaml
LDAP_ENABLED: "true"
LDAP_AUTO_PROVISION: "false"
LDAP_PROVIDER_ID: primary-openldap
LDAP_URL: ldap://ldap.example.com:389
LDAP_BASE_DN: ou=people,dc=example,dc=com
LDAP_BIND_DN: cn=svc-webssh,ou=services,dc=example,dc=com
LDAP_USER_FILTER: "(&(objectClass=inetOrgPerson)(uid={username})(!(pwdAccountLockedTime=*)))"
LDAP_UNIQUE_ID_ATTRIBUTE: entryUUID
```

Remove the `pwdAccountLockedTime` clause if that operational attribute is not
available, and replace it with the directory's actual disabled-account rule.

## Populate the opt-in secret volume

The LDAP overlay creates `webssh_auth_secrets` and mounts it read-only at
`/run/webssh-auth` in WebSSH. The standard Compose deployment does not declare
or mount this volume.

Set the bind password with a hidden interactive prompt:

```bash
docker compose -f docker-compose.yml -f docker-compose.ldap.yml --profile ldap-tools run --rm ldap-tools set-password
```

Install and validate the CA bundle on Linux or macOS:

```bash
docker compose -f docker-compose.yml -f docker-compose.ldap.yml --profile ldap-tools run --rm -T ldap-tools install-ca --stdin < company-ca.pem
```

PowerShell equivalent:

```powershell
Get-Content -Raw .\company-ca.pem | docker compose -f docker-compose.yml -f docker-compose.ldap.yml --profile ldap-tools run --rm -T ldap-tools install-ca --stdin
```

Check only file presence; the helper never prints their contents:

```bash
docker compose -f docker-compose.yml -f docker-compose.ldap.yml --profile ldap-tools run --rm ldap-tools status
```

The helper validates input, caps file sizes, writes atomically, and applies
private permissions. It is standalone, has no network access, and is the only
Compose service with write access to the LDAP volume. WebSSH mounts that volume
read-only whenever the LDAP overlay is selected. The helper still works if an
incomplete LDAP configuration prevents the Flask application from starting.

## Activate and link users

1. Verify that every empty value in `docker-compose.ldap.yml` is configured.
2. Start or recreate WebSSH with the overlay:
   `docker compose -f docker-compose.yml -f docker-compose.ldap.yml up -d`.
3. Review startup logs with
   `docker compose -f docker-compose.yml -f docker-compose.ldap.yml logs webssh`.
   WebSSH deliberately stops
   before serving if the secret, CA, URL, filter, or timeout configuration is
   unsafe.
4. Sign in with the local break-glass administrator.
5. Open **Admin - Settings - LDAP directory** and run **Check connection**.
   The browser receives only ready/unavailable, transport, and provider ID.
6. Keep `LDAP_AUTO_PROVISION: "false"` for explicit account lifecycle control.
   Create the target local WebSSH user, then choose **Link LDAP** on the Users
   tab and provide the directory username, administrator password, and exact
   target WebSSH username.
7. For larger directories, optionally set `LDAP_AUTO_PROVISION: "true"` and
   recreate WebSSH with the overlay. A verified first sign-in then creates a
   non-admin LDAP-managed account. Existing local usernames still require the
   explicit administrator linking flow.
8. Sign out and test the directory account. When LDAP is enabled, its
   `LDAP_PROVIDER_ID` is the default **Authentication Source**; local sign-in
   remains selectable.

Do one non-administrator pilot account before migrating more users.

For the strict production profile, keep the LDAP overlay before the production
overlay so the production settings remain authoritative:

```bash
docker compose -f docker-compose.yml -f docker-compose.ldap.yml -f docker-compose.production.yml up -d
```

## Rollback and recovery

To stop LDAP immediately, recreate WebSSH from the standard Compose file only:

```bash
docker compose -f docker-compose.yml up -d --force-recreate
```

This removes the LDAP environment and mount from the container. The named
secret volume remains stored but detached until the overlay is selected again.
Existing LDAP sessions are invalidated. Local accounts continue normally, but
linked LDAP accounts intentionally do not regain their old passwords.
Directory removal or filter exclusion revokes access without deleting the
account's stored WebSSH data; delete that data only through the normal explicit
administrator lifecycle.

To return one account to local authentication while LDAP is working, choose
**Manage LDAP**, provide the administrator password, exact target username, and
a new local password, then unlink it.

To remove only LDAP secret files after all identities have been unlinked and
LDAP is disabled:

```bash
docker compose -f docker-compose.yml -f docker-compose.ldap.yml --profile ldap-tools run --rm ldap-tools remove
```

Do not delete the normal WebSSH data volume. LDAP mappings live in the normal
database and are included in native backup/restore; bind credentials and the CA
remain in the separate secret volume and are intentionally not included.

## Troubleshooting

- **Application refuses to start:** run the standalone `status` helper and
  check the exact configuration error in container logs.
- **Certificate failure:** verify DNS, certificate SAN, system time, the full CA
  chain, and that the CA is PEM rather than DER or PKCS#12.
- **Zero or multiple matches:** test the search base/filter with the directory
  administrator. WebSSH never chooses one result from an ambiguous search.
- **AD user is found but cannot bind:** check disabled/locked/expired state,
  logon restrictions, and whether the DC accepts the supplied username flow.
- **LDAP outage signs users out:** this is intentional fail-closed behavior.
  Restore directory/TLS service; do not enable a password fallback.
- **Provider ID changed:** restore the original `LDAP_PROVIDER_ID`. It is part
  of every stable mapping and should remain constant for that directory.

## Local test laboratory

An Active Directory domain is not required for basic functional testing. The
opt-in lab under `tests/integration/ldap/` starts a TLS-enabled OpenLDAP server,
initializes the preconfigured secret volume, builds WebSSH, and exposes it on
`http://localhost:5050`. It uses test-only passwords and must never be deployed
as production infrastructure.

```bash
docker compose -f tests/integration/ldap/docker-compose.yml up --build
```

The lab validates generic LDAP behavior. `objectGUID`, AD disabled-account
filters, AD certificate enrollment, and domain-controller policy still require
an AD-specific acceptance test before production rollout.
