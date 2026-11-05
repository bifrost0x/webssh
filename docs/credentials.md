# Saved connection passwords

Administrators enable **Save passwords** in **Administration → Integrations**. No Compose change or restart is required. New installations require explicit activation. Passwords belong to individual users; enabling the feature does not grant administrators access to another user's secrets. HTTPS is required.

## Create and assign

Open **Hosts → Passwords**, beside SSH Keys. Give the entry a recognizable name, optionally suggest a username, and enter its password. Assign one entry to several of your SSH hosts, jump hosts or SMB sources. You can also create a password while configuring a new connection. Saving neither connects nor changes the password on the remote server.

The host's username remains authoritative. The same assigned SSH credential serves terminal, SFTP and supported Automation connections. In Quick Connect choose **Saved password** as the authentication method, then select an entry. Connecting authorizes that exact destination without creating a permanent host. Manual one-time input remains available.

The detail view shows assigned destinations. **Assign to hosts** opens a searchable checklist of password-authenticated SSH hosts with their addresses, usernames and current assignments. Select the hosts and apply the changes; filtering preserves your selection. If a batch partly fails, completed assignments remain visible and the remaining selections are preserved for retry. You can also select the saved password in a host, jump-host or SMB editor. Save pending password edits before changing assignments.

Each saved resource has exactly one password assignment. Selecting a different entry shows the previous and new password names and asks for confirmation. A checklist batch presents all replacements together. Cancel leaves the assignments unchanged; concurrent assignment changes are rejected and require a fresh review. Applying the same password to the same destination preserves existing schedule authorization.

Routine password creation, replacement and assignment use your authenticated WebSSH session without another account-password prompt. HTTPS, CSRF protection, ownership checks and single-use intents bound to the exact change remain enforced. Immediate Automation execution and unattended schedule approval still require explicit account verification.

**Replace password** accepts a new value; saved passwords are never returned by the API or displayed. Renaming does not replace a secret. Remove assignments before deleting an entry in use.

Changing address, port, username, authentication mode, jump route, SMB domain or share invalidates its destination approval. Explicitly approve the new target before reuse. Names and groups do not change its access identity. SSH host-key verification, ownership, interactive MFA, protocol policy and quotas remain enforced.

## Availability and encryption

New credentials have no separate passphrase or 15-minute unlock. The server decrypts them for authorized connections and explicitly approved schedules. The browser receives references, not saved passwords.

Replacing a used password, changing its assignment, disabling storage or revoking account access invalidates pending authorization. An unrelated credential change does not interrupt another credential. Already authenticated manual terminals and file sources remain open when storage is disabled. Disabling preserves encrypted records.

Named passwords use AES-256-GCM with fresh 96-bit nonces. HKDF derives domain-separated keys from the application's SECRET_KEY, bound to record ID and owning account incarnation. Encryption at rest cannot protect against control of the running server or possession of both data and the application secret. Python cannot guarantee erasure of every temporary memory copy.

Preserve the exact original **SECRET_KEY** securely with deployment recovery material. Do not assume a data-only archive contains an externally supplied environment secret. Credential files cannot be decrypted with a different key.

Native backup exports exclude named password records (`credentials.json`), legacy `automation-vault.json`, SSH key directories including metadata, and quarantined `deleted_users` data. Normal restore ignores these files even in older archives and removes existing copies to prevent credential reuse by a different restored account. Recreate passwords, reimport SSH keys and reassign credentials after restore; review and re-enable schedules.

Historical backups are not rewritten and may still contain replaced/deleted passwords and SSH keys. Rotate credentials on the actual servers when those copies must stop working. Private internal recovery snapshots retain encrypted credentials for failed-restore or secret-rotation rollback; they are separate from downloadable exports and require restricted access and their own retention and cleanup. Backups still retain account authentication data and may retain the application secret. Encrypt them separately and store them off-host. These exclusions do not detect arbitrary secrets embedded in commands, notes or run history.

Never put secrets in commands, exported profiles, URLs, browser storage or logs.

## Existing passphrase vaults

Existing automation-vault.json files remain intact. **Import existing vault** asks for the old passphrase once and imports named entries and valid assignments. The old ciphertext is not deleted. Failed import leaves it recoverable; repeating the same source revision does not duplicate records. Changed old destination bindings require explicit correction.

New installations need no vault passphrase. A lost old passphrase cannot be repaired by the new store: import the existing vault using the original passphrase or enter remote passwords again. Native backup restore does not restore the legacy vault. Older versions do not understand the named store; downgrade requires a compatible backup, not overwriting new data.
