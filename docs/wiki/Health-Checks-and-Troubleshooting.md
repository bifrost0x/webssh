# Health Checks and Troubleshooting

WebSSH exposes separate liveness and readiness endpoints. Use both; they answer different operational questions.

## Liveness: `/health`

```bash
curl -fsS http://127.0.0.1:5000/health
```

An operating process returns HTTP 200 with:

```json
{"status":"ok"}
```

Liveness does not prove that the database, data directory, or runtime admission is ready. A supervisor can use it to detect a dead process without restarting an instance merely because it is intentionally in maintenance.

## Readiness: `/ready`

```bash
curl -fsS http://127.0.0.1:5000/ready
```

Readiness verifies:

- maintenance mode is inactive;
- the runtime lifecycle accepts new work;
- the SQLite database responds;
- the data directory passes its read/write probe.

A failed category produces HTTP 503. Use readiness for reverse-proxy or orchestrator traffic admission and during graceful shutdown.

## Container status

```bash
docker compose ps
docker compose logs --tail=200 webssh
```

If the service repeatedly restarts, inspect the first startup error rather than only the last health-check failure. Common causes are an invalid production configuration, missing/incorrect secret permissions, an unwritable data volume, or a port collision.

## Browser cannot connect

Check in this order:

1. `/health` and `/ready` on the application host.
2. Reverse-proxy upstream address and port.
3. WebSocket/Socket.IO upgrade forwarding.
4. Exact public scheme and host in `CORS_ORIGINS`.
5. Whether `TRUSTED_PROXIES` matches the real number of forwarding layers.
6. Secure-cookie behavior over HTTPS.
7. Subfolder prefix consistency if `APPLICATION_ROOT` is set.

An HTTP page with a `Secure` session cookie will not maintain an authenticated session. Do not disable secure cookies to mask a broken production TLS path.

## SSH connection is rejected

Distinguish these failures:

- Target policy: `BLOCK_INTERNAL_SSH` or an allowlist rejected the resolved address.
- Capacity: global/per-user SSH or socket quota is exhausted.
- Network: DNS, routing, firewall, or SSH port is unavailable from the WebSSH host.
- Authentication: remote username, password, key, agent, or Jump Host chain failed.
- Host key: the server is unknown and awaits trust, or a pinned key changed.

For a changed host key, validate the new fingerprint independently before revoking the old record. Do not disable verification.

## SFTP or transfer problems

Bulk transfers use HTTP, so proxy body-size, buffering, and timeout settings can fail even when terminal Socket.IO works. Also inspect:

- per-user and global transfer slots;
- temporary-byte quotas and free disk space;
- remote file permissions and SFTP subsystem availability;
- quick-connection lifetime and remote idle timeouts;
- upload size and editor-content limits.

The file workspace supports SFTP sources and opt-in SMB sources. If the SMB
control is disabled, confirm that `SMB_ENABLED=true` and a non-empty exact
`SMB_ALLOWED_TARGETS` allowlist reach the container. SMB remains default-off.

For SMB, test from the WebSSH container's network namespace rather than only
from the Docker host. The configured hostname or IP must resolve there and be
reachable on TCP 445. Services in separate Compose projects need a shared
external network or a LAN address published by the SMB host; WebSSH itself does
not expose an SMB port.

Use the workspace result to narrow the failure:

- connection rejected: verify allowlist, DNS, TCP 445, credentials, SMB 3.1.1,
  signing, encryption, and secure negotiation; for Active Directory or TrueNAS,
  try DNS domain `example.com` with username `alice`, or leave the domain empty
  and use a UPN such as `alice@example.com`; NetBIOS names may not be accepted;
- connection opens but listing fails: verify share name and list/read ACLs;
- root is labeled read-only: the account can list the root but the server
  denied both file and directory creation there;
- root access is unknown: the server could not conclusively answer one or more
  non-mutating access checks; test the intended operation;
- an upload or copy fails in a nested folder: inspect that folder's ACL, quota,
  free space, and delete/rename rights even if root write access was confirmed;
- replace is unavailable: grant atomic rename/delete-child rights or choose a
  new filename; WebSSH does not delete the old destination first.
- an editor reports manual recovery: preserve the named temporary and backup
  files, recover the newer verified content, and only then remove the artifacts;
- a move times out: refresh both source and destination folders before retrying
  because the server may have completed the rename after the browser lost its
  acknowledgement;
- cancellation remains pending: inspect the transfer reason and server logs;
  the first request is idempotent and its acknowledgement is authoritative, so
  repeated clicks are neither required nor useful.

For a server-side SMB connection failure, the dialog includes a reference such
as `SMB-A1B2C3D4E5F6`. Search `DATA_DIR/logs/app.log` or structured container
logs for that exact reference. The matching record contains a stable result
code plus sanitized diagnostic fields:

- `target_resolution`: allowlist, DNS, or resolved-target handling;
- `transport_negotiate`: TCP 445 or SMB negotiation;
- `security_requirements`: SMB 3.1.1, signing, encryption, or secure negotiate;
- `session_authentication`: domain, username, password, or account state;
- `share_access`: share name, availability, or root ACL;
- `lifecycle`: quota reservation, publication, shutdown, or cleanup handling.

`cause_type` identifies only the exception class and `nt_status`, when present,
is the fixed-width SMB status code. WebSSH deliberately does not return or log
the backend exception message because it can contain credentials, server names,
or share paths. A support report should contain the reference, result code,
phase, cause type, NT status, WebSSH version or commit, SMB server product and
version, and reproduction steps, but never the SMB password.

The transfer queue shows the stable reason returned by the server. A bare
generic failure indicates an unclassified backend problem and should be
correlated with the sanitized server log fields `operation`, `result_code`,
and `exception_type`.

## LDAP/AD sign-in fails

Review the dedicated [LDAP troubleshooting sequence](LDAP-and-Active-Directory#troubleshooting). The most important distinction is whether service bind/search failed, the user did not match filters, TLS validation failed, user credential bind failed, or no enabled local account is linked to the resulting directory identity.

LDAP auto-provisioning is optional and disabled by default with
`LDAP_AUTO_PROVISION=false`. When explicitly enabled, WebSSH creates only a
non-admin account after a successful directory bind. Existing local usernames
are never claimed automatically, ambiguous or colliding identities fail
closed, and operators should retain a tested local break-glass administrator.

## OIDC sign-in fails

Verify issuer discovery, exact redirect URI, client secret file permissions,
state/nonce lifetime, system clock, and any allowed-subject/domain policy. An
email match does not replace the exact issuer-plus-subject identity link. For
MFA or administrator step-up failures, also verify the signed `acr`/`amr`
claims, configured assurance mappings, and provider support for requested
`prompt=login`, `max_age=0`, and `acr_values` parameters.

## Capacity symptoms

Slow or refused work can result from thread, socket, SSH, transfer, temporary-byte, or background-worker admission. Compare live diagnostics with every related limit. Preserve at least four HTTP threads and do not raise sockets above available Gunicorn capacity.

## Safe evidence collection

When requesting help, include:

- exact WebSSH version or commit;
- deployment profile and sanitized effective Compose configuration;
- `/health` and `/ready` status;
- relevant log timestamps, diagnostic reference, phase, and error class;
- reverse-proxy product and URL path;
- whether the target is local, private, public, LDAP, OIDC, or Tailscale;
- steps to reproduce.

Remove passwords, cookies, tokens, private keys, recovery codes, bind credentials, and sensitive hostnames/IP addresses. Report suspected vulnerabilities privately as described in `SECURITY.md`.
