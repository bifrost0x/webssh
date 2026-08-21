# Administration, Audit, and Diagnostics

WebSSH's administration interface combines account lifecycle controls, runtime diagnostics, security auditing, host-key visibility, and native backup operations. Administrative access is necessary but is not a substitute for recent reauthentication on sensitive actions.

## Administrative responsibilities

Administrators can:

- create, enable, disable, and remove local accounts;
- assign or remove administrator privileges;
- inspect runtime and connection diagnostics;
- export security audit records and update retention settings;
- manage native backup and restore operations;
- review host-key state and security-relevant configuration;
- link or unlink supported external identities under the applicable safeguards.

Disabling or deleting a user revokes live activity, including Socket.IO, SSH, pooled connections, and transfers. Deletion first quarantines the user's data directory and rolls back that move if the database operation fails.

## Recent authentication

Sensitive operations require a recent local-password confirmation. This limits damage from an unattended authenticated browser session. External identities do not bypass this safeguard; maintain a controlled local administrator credential and recovery process.

## Security audit log

Security-relevant actions are written to `DATA_DIR/logs/security_audit.log`. Rotation uses `AUDIT_LOG_MAX_BYTES` and `AUDIT_LOG_BACKUP_COUNT`; defaults are 10 MiB and five backups.

Audit records are intended for investigation and accountability. They do not contain passwords, authentication tokens, private-key material, or file contents. Protect the log directory because event metadata can still reveal usernames, hosts, IP addresses, and administrative activity.

## Audit export

The administrator export endpoint applies server-side filtering and scans at most 50,000 records per request. If a result is incomplete, WebSSH marks it as truncated in metadata and response headers. Narrow the time range or filters instead of assuming a truncated export is complete.

Retention updates are authenticated administrator operations and are themselves auditable. Rotation and retention protect local disk capacity; forward logs to an external system if the threat model requires tamper-resistant or longer-term retention.

## Live diagnostics

Diagnostics expose bounded information about:

- admitted Socket.IO connections;
- active SSH and quick connections;
- transfers and temporary storage;
- background executor activity;
- runtime shutdown or maintenance state;
- configured capacity limits.

Use diagnostics to compare demand with `GUNICORN_THREADS`, socket admission, SSH quotas, transfer quotas, and background workers. Avoid treating a single counter as the entire capacity picture.

## Host-key administration

Host-key trust is stored per user. First-use trust, changed-key rejection, and explicit revocation are covered in [SSH Connections and Host Keys](SSH-Connections-and-Host-Keys). Administrators should not globally bypass a user's trust decision to resolve a connection error.

## Operational health

- `GET /health` proves process liveness.
- `GET /ready` checks whether the instance can accept work.

Readiness fails during maintenance, shutdown admission closure, database failure, or a failed data-directory probe. Details are in [Health Checks and Troubleshooting](Health-Checks-and-Troubleshooting).

## Administration checklist

1. Keep at least one tested local administrator and recovery path.
2. Require HTTPS and a trusted reverse proxy for Internet exposure.
3. Review disabled accounts, linked identities, and host-key changes regularly.
4. Export or forward audit data according to the required retention period.
5. Test native backups and restores on a separate instance.
6. Monitor capacity and temporary disk usage before raising quotas.
7. Apply upgrades only after reviewing configuration changes and release notes.
