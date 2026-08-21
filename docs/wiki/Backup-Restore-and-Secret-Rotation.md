# Backup, Restore, and Secret Rotation

WebSSH provides native administrator and CLI workflows for backing up persistent state, validating archives, restoring an installation, and rotating a container-managed `SECRET_KEY`.

Backups are highly sensitive. An archive can contain user configuration, host information, the database, encrypted private keys, and the persisted application secret. Store it like a credential vault export.

## What a native backup contains

The archive covers the persistent `DATA_DIR` state required to restore the instance. Transient logs, temporary uploads, incomplete transfers, and runtime-only SSH channels are excluded.

Current archives use format version 2. The verifier also understands legacy format version 1/schema 0 for compatibility. Validation checks the manifest, file checksums, declared sizes, member paths, member count, compression behavior, and archive-wide limits before restore.

## Online backup in the web interface

An administrator can create a consistent backup while the service is online. SQLite uses its backup API and file writers are coordinated so that the archive represents a coherent point in time.

The completed download is one-time, session-bound, and expires after `BACKUP_DOWNLOAD_TTL` seconds, which defaults to 600. Temporary archive construction occurs outside `DATA_DIR` in an instance-specific namespace.

Do not rely on the short-lived browser download as retention. Move the archive immediately to encrypted, access-controlled backup storage.

## Restore in the web interface

Restore is deliberately disruptive and strongly confirmed:

1. Upload the archive.
2. Let WebSSH validate format and safety limits.
3. Review the restore target and warnings.
4. Complete both confirmations, including the exact `RESTORE` phrase and administrator password.
5. WebSSH enters maintenance mode and stops accepting new work.
6. Active sessions and transfers are closed.
7. An emergency rollback archive is created.
8. Persistent state is replaced and sessions are invalidated.
9. The process terminates intentionally so the service manager can start a clean runtime.

If an interruption occurs during replacement, the restore workflow attempts rollback from the emergency archive. Still take an independent backup before every restore and keep it outside the instance.

## CLI backup and restore

CLI operations require every WebSSH process that uses the same `DATA_DIR` to be stopped. This avoids concurrent writers outside the coordinated web workflow.

Discover exact options in the installed version:

```bash
flask --app start:app backup create --help
flask --app start:app backup verify --help
flask --app start:app backup restore --help
```

For a container deployment, execute the command in a one-off container with the same data volume and configuration, while the normal application container is stopped.

## Safety limits

Default operational limits include:

| Setting | Default |
|---|---:|
| Upload size | 1 GiB |
| Operation timeout | 30 minutes |
| One-time download lifetime | 10 minutes |
| Archive members | 10,000 |
| Individual uncompressed file | 1 GiB |
| Total uncompressed content | 10 GiB |
| Compression ratio | 200:1 |
| Manifest size | 10 MiB |

Reverse-proxy body-size and timeout settings must allow the same operation. Do not raise limits without assessing disk exhaustion and decompression-bomb risk.

## Secret-key rotation

The supported rotation command re-encrypts persisted secrets when WebSSH manages `DATA_DIR/secret_key`:

```bash
flask --app start:app rotate-secret-key --help
```

All WebSSH processes must be stopped. Take and verify a backup first. The command changes the root used for encrypted per-user SSH keys and invalidates signed session state, so a partial or interrupted manual replacement can make persisted credentials unreadable.

If `SECRET_KEY` comes from an external environment variable or secret manager, rotating only the external value is not sufficient. Plan a controlled migration that keeps the old key available while persisted secrets are re-encrypted. The built-in command is scoped to the container-managed persisted secret.

## Restore drill

Test the full sequence on an isolated instance:

1. Create and download a backup.
2. Verify it with the CLI.
3. Start a disposable instance with an empty data volume.
4. Restore the archive.
5. Confirm local, LDAP/OIDC where applicable, Passkey, SSH, SFTP, and host-key data.
6. Confirm that old browser sessions are invalid.
7. Record the observed recovery time and required secret material.

An untested archive is not a verified recovery capability.
