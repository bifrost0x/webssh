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

The file workspace supports SFTP sources. SMB is not a supported backend even if a disabled placeholder appears in the interface.

## LDAP/AD sign-in fails

Review the dedicated [LDAP troubleshooting sequence](LDAP-and-Active-Directory#troubleshooting). The most important distinction is whether service bind/search failed, the user did not match filters, TLS validation failed, user credential bind failed, or no enabled local account is linked to the resulting directory identity.

WebSSH intentionally does not auto-provision LDAP users.

## OIDC sign-in fails

Verify issuer discovery, exact redirect URI, client secret file permissions, state/nonce lifetime, system clock, and any allowed-subject/domain policy. An email match does not replace the exact issuer-plus-subject identity link.

## Capacity symptoms

Slow or refused work can result from thread, socket, SSH, transfer, temporary-byte, or background-worker admission. Compare live diagnostics with every related limit. Preserve at least four HTTP threads and do not raise sockets above available Gunicorn capacity.

## Safe evidence collection

When requesting help, include:

- exact WebSSH version or commit;
- deployment profile and sanitized effective Compose configuration;
- `/health` and `/ready` status;
- relevant log timestamps and error class;
- reverse-proxy product and URL path;
- whether the target is local, private, public, LDAP, OIDC, or Tailscale;
- steps to reproduce.

Remove passwords, cookies, tokens, private keys, recovery codes, bind credentials, and sensitive hostnames/IP addresses. Report suspected vulnerabilities privately as described in `SECURITY.md`.
