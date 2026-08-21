# LDAP and Active Directory

LDAP authentication is optional and disabled by default. The standard Compose
deployment creates no LDAP volume, mount, helper, route, or background job.
Opt in with `docker-compose.ldap.yml`.

## Security model

- `ldap://` always upgrades with StartTLS before any bind.
- `ldaps://` starts TLS immediately.
- Plain LDAP authentication and disabled certificate verification are not
  supported.
- A least-privilege service account performs read-only user searches.
- The submitted user password is used only for the final user bind and is never
  stored.
- Usernames are escaped as RFC 4515 filter values.
- Searches are subtree-scoped, limited to two results, and must resolve to
  exactly one entry.
- An administrator links a stable directory identity to an existing WebSSH
  account. There is no automatic provisioning or username-only trust.
- Linked LDAP users cannot be administrators and cannot fall back to local
  passwords, passkeys, recovery codes, or OIDC.
- LDAP sessions are periodically revalidated and fail closed.

Keep at least one unlinked local break-glass administrator.

## Directory information required

Collect these values from the directory administrator:

1. An LDAP server DNS name covered by the server certificate.
2. `ldap://host:389` with StartTLS or `ldaps://host:636`.
3. The user search base DN.
4. A read-only bind DN and password.
5. A PEM CA bundle containing the issuer chain needed by WebSSH.
6. A user filter containing exactly one literal `{username}` placeholder.
7. A stable unique-ID attribute: usually `entryUUID` for OpenLDAP or
   `objectGUID` for Active Directory.
8. The directory's real disabled or locked account rule.

DNS and system time must work inside the WebSSH container. Do not use an IP
address when the certificate contains only a DNS name.

## Configure the Compose overlay

Edit `docker-compose.ldap.yml` and fill every empty directory value. Use the
base and LDAP files from the same WebSSH release or commit.

### Active Directory example

```yaml
services:
  webssh:
    environment:
      LDAP_ENABLED: "true"
      LDAP_PROVIDER_ID: corp-ad
      LDAP_URL: ldaps://dc01.ad.example.com:636
      LDAP_BASE_DN: OU=People,DC=ad,DC=example,DC=com
      LDAP_BIND_DN: CN=svc-webssh,OU=Service Accounts,DC=ad,DC=example,DC=com
      LDAP_USER_FILTER: "(&(objectCategory=person)(objectClass=user)(sAMAccountName={username})(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
      LDAP_UNIQUE_ID_ATTRIBUTE: objectGUID
```

The final filter clause excludes disabled AD accounts. If access is restricted
to a group, use a directory-approved `memberOf` rule. Nested group semantics
vary and must be validated by the AD administrator.

### OpenLDAP example

```yaml
services:
  webssh:
    environment:
      LDAP_ENABLED: "true"
      LDAP_PROVIDER_ID: primary-openldap
      LDAP_URL: ldap://ldap.example.com:389
      LDAP_BASE_DN: ou=people,dc=example,dc=com
      LDAP_BIND_DN: cn=svc-webssh,ou=services,dc=example,dc=com
      LDAP_USER_FILTER: "(&(objectClass=inetOrgPerson)(uid={username})(!(pwdAccountLockedTime=*)))"
      LDAP_UNIQUE_ID_ATTRIBUTE: entryUUID
```

Remove or replace the `pwdAccountLockedTime` clause if that operational
attribute is not available.

## Configuration reference

| Variable | Default | Requirement |
|---|---:|---|
| `LDAP_ENABLED` | `false` | Enable the subsystem |
| `LDAP_PROVIDER_ID` | `default` | Stable 1-64 character local provider identifier |
| `LDAP_URL` | empty | Exact `ldap://` or `ldaps://` server URL |
| `LDAP_BASE_DN` | empty | User subtree base |
| `LDAP_BIND_DN` | empty | Least-privilege search account DN |
| `LDAP_BIND_PASSWORD_FILE` | `/run/webssh-auth/ldap_bind_password` | Absolute private file path |
| `LDAP_CA_FILE` | `/run/webssh-auth/ldap_ca.pem` | Absolute PEM CA bundle path |
| `LDAP_USER_FILTER` | empty | Exactly one `{username}` placeholder |
| `LDAP_UNIQUE_ID_ATTRIBUTE` | empty | LDAP attribute name or numeric OID |
| `LDAP_CONNECT_TIMEOUT` | `5` | 1-15 seconds |
| `LDAP_OPERATION_TIMEOUT` | `5` | 1-30 seconds |
| `LDAP_SESSION_REVALIDATION_SECONDS` | `300` | 60-3600 seconds |
| `LDAP_LOGIN_RATE_LIMIT` | `5 per minute` | Per-IP login and diagnostic limit |

When LDAP is disabled, WebSSH does not read the secret files.

## Populate the secret volume

The overlay creates `webssh_auth_secrets`. WebSSH mounts it read-only at
`/run/webssh-auth`. The helper service is the only Compose service with write
access; it has no network, runs read-only apart from the volume, drops all
capabilities, and uses `no-new-privileges`.

Set the bind password with a hidden interactive prompt:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.ldap.yml \
  --profile ldap-tools \
  run --rm ldap-tools set-password
```

Install and validate the CA bundle on Linux or macOS:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.ldap.yml \
  --profile ldap-tools \
  run --rm -T ldap-tools install-ca --stdin < company-ca.pem
```

PowerShell:

```powershell
Get-Content -Raw .\company-ca.pem | docker compose `
  -f docker-compose.yml `
  -f docker-compose.ldap.yml `
  --profile ldap-tools `
  run --rm -T ldap-tools install-ca --stdin
```

Check only file presence; contents are never printed:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.ldap.yml \
  --profile ldap-tools \
  run --rm ldap-tools status
```

The helper validates input, caps file sizes, writes atomically, and applies
private permissions. It remains usable when incomplete LDAP configuration stops
the Flask app from starting.

## Activate LDAP

1. Confirm every empty overlay value is filled.
2. Populate the bind password and CA.
3. Inspect the effective configuration:

   ```bash
   docker compose \
     -f docker-compose.yml \
     -f docker-compose.ldap.yml \
     config
   ```

4. Start or recreate WebSSH:

   ```bash
   docker compose \
     -f docker-compose.yml \
     -f docker-compose.ldap.yml \
     up -d
   ```

5. Review startup logs:

   ```bash
   docker compose \
     -f docker-compose.yml \
     -f docker-compose.ldap.yml \
     logs webssh
   ```

Unsafe URL, secret, CA, filter, attribute, and timeout settings stop startup.

For production, apply the production overlay last:

```bash
export WEBSSH_ORIGIN=https://ssh.example.com
docker compose \
  -f docker-compose.yml \
  -f docker-compose.ldap.yml \
  -f docker-compose.production.yml \
  up -d
```

## Link users

1. Sign in with the local break-glass administrator.
2. Open **Admin → Settings → LDAP directory**.
3. Run **Check connection**. The browser receives only readiness category,
   transport, and provider ID, never secrets.
4. Create the target standard WebSSH account if it does not exist.
5. On the Users tab, select **Link LDAP**.
6. Enter the directory username, administrator password, and exact target
   WebSSH username.
7. Sign out and test **Sign in with LDAP**.

Start with one non-admin pilot.

Linking stores the stable provider and subject plus the current DN and directory
username. A renamed DN can be updated after successful authentication as long as
the stable ID still matches.

Linking destroys the account's dormant local password and removes passkeys,
recovery codes, and OIDC mappings. This prevents weaker fallback paths.

## Session revalidation

Every linked account is revalidated at the configured interval. WebSSH revokes
browser, Socket.IO, SSH, transfer, and pooled-connection access when:

- LDAP is disabled;
- the directory is unavailable;
- certificate validation fails;
- the user disappears;
- the stable ID changes;
- the account no longer matches the filter;
- the mapping is missing or no longer eligible.

An LDAP outage therefore signs users out by design.

## Disable LDAP immediately

Recreate WebSSH from the base file only:

```bash
docker compose up -d --force-recreate
```

This removes LDAP environment and mounts from the WebSSH container. The named
secret volume remains detached. Existing LDAP sessions are invalidated, and
linked users do not regain old passwords.

## Return one user to local authentication

While LDAP is working, choose **Manage LDAP**, provide the administrator
password, exact target username, and a new local password, then unlink the
identity. The new password establishes a fresh local credential.

## Remove LDAP secrets

After all identities are unlinked and LDAP is disabled:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.ldap.yml \
  --profile ldap-tools \
  run --rm ldap-tools remove
```

Do not delete the normal WebSSH data volume. LDAP mappings live in SQLite and
are covered by native backup/restore. The bind password and CA remain in the
separate volume and are intentionally excluded.

## Troubleshooting

### Application refuses to start

Run the standalone `status` helper, then read the exact configuration error in
the WebSSH logs.

### Certificate failure

Verify DNS, certificate SAN, system time, the complete issuer chain, and PEM
encoding. DER and PKCS#12 files are not CA bundles for this setting.

### Zero or multiple search results

Test the search base and filter with the directory administrator. WebSSH never
selects one entry from an ambiguous result.

### AD user is found but bind fails

Check disabled, locked, expired, and logon-restricted state plus the domain
controller's accepted username flow.

### LDAP outage signs users out

Restore directory and TLS service. Do not add a password fallback.

### Provider ID changed

Restore the original `LDAP_PROVIDER_ID`. It is part of every mapping and must
remain stable for the lifetime of that directory integration.

## Disposable OpenLDAP laboratory

The integration lab validates generic LDAP behavior without an AD domain:

```bash
docker compose \
  -f tests/integration/ldap/docker-compose.yml \
  up --build
```

It exposes WebSSH on `http://localhost:5050` and uses test-only passwords.
Never deploy it as production infrastructure.

The lab does not replace AD-specific acceptance testing for `objectGUID`,
disabled-account filters, certificate enrollment, or domain-controller policy.
