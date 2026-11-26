"""Static description of every data kind and of every user-created entity.

Each entry names where the data lives, how it is encoded and which
application function defines it. ``{SECRET_KEY}``, ``{user_id}`` and
``{incarnation}`` are placeholders; ``incarnation`` is
``users.created_at.isoformat()`` of the naive UTC value SQLite returns, so a
zero microsecond part is omitted ("2026-11-02T09:00:00").
"""

PBKDF2 = 'PBKDF2-HMAC-SHA256'
FERNET = ('Fernet spec 0x80 token: AES-128-CBC + HMAC-SHA256, 64-bit timestamp; '
          'key = urlsafe_b64encode(derived 32 bytes)')

DATA_KINDS = [
    {'id': 'secret_key', 'location': 'data/secret_key',
     'format': 'ASCII, 64 lowercase hex characters, LF, mode 0600',
     'source': 'entrypoint.sh (persisted SECRET_KEY); config.SECRET_KEY'},
    {'id': 'sqlite_database', 'location': 'data/app.db',
     'format': 'SQLite 3; DateTime columns as naive UTC text '
               '"YYYY-MM-DD HH:MM:SS.ffffff"; Boolean as 0/1',
     'source': 'app/models.py, app/automation_schedule.py (SQLAlchemy models)'},
    {'id': 'password_hash', 'location': 'users.password_hash',
     'format': 'bcrypt modular crypt "$2b$12$<22 salt><31 hash>"',
     'algorithm': 'bcrypt', 'parameters': {'cost': 12, 'input': 'UTF-8 password, at most 72 bytes'},
     'source': 'app/models.py User.set_password/check_password; app/auth.py password_exceeds_bcrypt_limit',
     'note': 'Directory- and GitHub-managed accounts hold a random unknown password.'},
    {'id': 'ssh_private_key_at_rest', 'location': 'data/users/user_{user_id}/keys/<uuid>.pem',
     'format': 'raw Fernet token bytes (no newline); legacy files may hold plaintext PEM',
     'algorithm': FERNET,
     'parameters': {'kdf': PBKDF2, 'password': '"{SECRET_KEY}:{user_id}" UTF-8',
                    'salt': 'webssh_key_encryption_v1', 'iterations': 600000, 'length': 32},
     'source': 'app/key_encryption.py _derive_key, encrypt_key_content, is_encrypted, read_key_content',
     'plaintext': 'OpenSSH or traditional PEM private key text; see values.ssh_keys'},
    {'id': 'ssh_key_metadata', 'location': 'data/users/user_{user_id}/keys/keys.json',
     'format': 'JSON {schema_version: 2, keys: [{id, name, filename, key_type, encrypted, uploaded_at}]}',
     'source': 'app/key_manager.py save_key, _valid_key_document'},
    {'id': 'totp_secret', 'location': 'totp_authenticators.encrypted_secret, totp_enrollments.encrypted_secret',
     'format': 'BLOB holding a Fernet token', 'algorithm': FERNET,
     'parameters': {'kdf': PBKDF2, 'password': '"{SECRET_KEY}:totp:{user_id}" UTF-8',
                    'salt': 'webssh-mfa-totp-v1', 'iterations': 600000, 'length': 32},
     'plaintext': 'RFC 4648 base32 secret, 32 characters (160 bits)',
     'verification': 'RFC 6238 HMAC-SHA1, 6 digits, 30 s step, window -1..+1, '
                     'step must exceed last_accepted_step',
     'source': 'app/mfa_crypto.py, app/totp_service.py'},
    {'id': 'recovery_code', 'location': 'recovery_codes.code_hash',
     'format': 'BLOB, 32 bytes',
     'algorithm': 'SHA-256(b"webssh-recovery-code-v1\\x00" + ASCII(upper(code) without whitespace))',
     'plaintext': 'XXXX-XXXX-XXXX-XXXX-XXXX, uppercase hex groups', 'source': 'app/recovery_service.py'},
    {'id': 'github_client_secret', 'location': 'github_auth_configuration.encrypted_client_secret',
     'format': 'BLOB holding a Fernet token', 'algorithm': FERNET,
     'parameters': {'kdf': PBKDF2, 'password': '"{SECRET_KEY}:github-auth:configuration" UTF-8',
                    'salt': 'webssh-github-auth-config-v1', 'iterations': 600000, 'length': 32},
     'source': 'app/github_auth_crypto.py, app/github_auth_service.py update_settings'},
    {'id': 'named_credential', 'location': 'data/users/user_{user_id}/credentials.json',
     'format': 'JSON {version: 1, credentials: {id: {id, name, username, version, updated_at, ciphertext}}, '
               'assignments: {resource_id: {credential_id, fingerprint, generation}}, imports: []}; '
               'ciphertext = base64(nonce[12] || AES-GCM ciphertext+tag)',
     'algorithm': 'AES-256-GCM, key = HKDF-SHA256(ikm=SECRET_KEY UTF-8, '
                  'salt=b"webssh-named-credential-master-v1", info=context, length=32), AAD = context',
     'parameters': {'context': 'compact JSON ["webssh-named-credentials-v1", {user_id} (int), '
                               '"{incarnation}", "<record id>"]'},
     'source': 'app/credential_crypto.py, app/credential_store.py'},
    {'id': 'automation_vault', 'location': 'data/users/user_{user_id}/automation-vault.json',
     'format': 'JSON {version: 2, kdf: "scrypt-131072-8-1", salt, nonce, ciphertext} (standard base64)',
     'algorithm': 'AES-256-GCM, key = scrypt(passphrase UTF-8, salt[16], N=131072, r=8, p=1, len=32)',
     'parameters': {'aad': '"webssh-automation-vault-v{version}:{user_id}:{incarnation}"',
                    'plaintext': 'compact JSON {profile_id: {fingerprint, password, generation}}'},
     'source': 'app/automation_vault.py', 'note': 'version 1 (no generation field) is still readable'},
    {'id': 'profile_fingerprint', 'location': 'credentials.json assignments, vault records',
     'algorithm': 'SHA-256 hex of json.dumps(fields, sort_keys=True, separators=(",", ":"))',
     'source': 'app/automation_store.py profile_fingerprint, digest'},
    {'id': 'webauthn_credential', 'location': 'webauthn_credentials',
     'format': 'credential_id raw BLOB; public_key = COSE_Key CBOR BLOB as returned by '
               'py_webauthn verify_registration_response; sign_count INTEGER; transports JSON text',
     'parameters': {'rp_id': 'WEBAUTHN_RP_ID', 'origin': 'WEBAUTHN_ORIGIN',
                    'user_handle': 'ASCII decimal user id', 'algorithms': 'EdDSA (-8), ES256 (-7), RS256 (-257)',
                    'user_verification': 'required', 'counter_rule': 'if stored > 0, new must be greater'},
     'source': 'app/webauthn_routes.py verify_registration, app/webauthn_service.py verify_assertion'},
    {'id': 'token_digest', 'location': 'authentication_sessions.session_hash and other *_hash columns',
     'algorithm': 'SHA-256 hex of the UTF-8 token string', 'source': 'app/models.py token_digest'},
    {'id': 'session_epoch', 'location': 'data/session_epoch',
     'format': '64 lowercase hex characters, LF, mode 0600',
     'semantics': 'every session cookie carries _auth_epoch; a mismatch logs the browser out',
     'source': 'app/session_epoch.py, app/__init__.py before_request'},
    {'id': 'flask_session_cookie', 'location': 'cookie "session" (SESSION_COOKIE_NAME)',
     'format': '[.]b64url(payload).b64url(int_to_bytes(unix_ts)).b64url(signature); '
               '"." prefix = zlib-compressed payload',
     'algorithm': 'itsdangerous URLSafeTimedSerializer, salt "cookie-session", key_derivation "hmac" '
                  '(derived key = HMAC-SHA1(SECRET_KEY, salt)), signature HMAC-SHA1, '
                  'serializer flask.json.tag.TaggedJSONSerializer',
     'parameters': {'max_age_seconds': 28800,
                    'payload': {'_user_id': '"{user_id}:{auth_generation}:{opaque}"',
                                '_auth_session': 'opaque; sha256 = authentication_sessions.session_hash',
                                '_auth_epoch': 'session_epoch value',
                                '_fresh': 'Flask-Login freshness flag',
                                '_id': 'Flask-Login identifier: SHA-512 hex of '
                                       'f"{remote_addr}|{user_agent_bytes!r}", e.g. '
                                       '"127.0.0.1|b\'golden-fixture-browser/1\'"; '
                                       'session_protection "basic"',
                                'csrf_token': 'not in the login response; Flask-WTF generate_csrf stores it when a page renders a token'}},
     'source': '.venv flask/sessions.py SecureCookieSessionInterface (Flask 3.1.3); '
               'itsdangerous/url_safe.py, timed.py, signer.py (2.2.0); flask_login/utils.py _create_identifier (0.6.3); app/auth_assurance.py _issue_browser_session'},
    {'id': 'login_device_cookie', 'location': 'cookie "session_device"',
     'algorithm': 'itsdangerous URLSafeTimedSerializer(SECRET_KEY, salt "webssh-login-device"), '
                  'defaults: key_derivation "django-concat", HMAC-SHA1',
     'parameters': {'payload': {'u': 'HMAC-SHA256(SECRET_KEY, b"webssh-login-username-v1\\x00" + casefold(username))',
                                'i': 'user id', 'g': 'auth_generation', 'n': 'nonce'}},
     'source': 'app/login_devices.py'},
    {'id': 'connection_history_scope', 'location': 'browser localStorage namespace (rendered into the page)',
     'algorithm': 'HMAC-SHA256(SECRET_KEY, "webssh-connection-history-v1\\0{user_id}\\0{username}\\0{incarnation}")',
     'source': 'app/browser_identity.py', 'note': 'changes lose the browser-side connection history'},
    {'id': 'known_hosts', 'location': 'data/known_hosts (global), data/users/user_{user_id}/known_hosts',
     'format': 'OpenSSH known_hosts lines; "@revoked" marker; "[host]:port" for non-22 ports',
     'source': 'app/host_key_store.py'},
    {'id': 'json_stores', 'location': 'data/users/user_{user_id}/*.json, data/app_settings.json',
     'format': 'JSON documents; schema_version per app/storage_migrations.py CURRENT_STORAGE_VERSIONS',
     'source': 'app/storage_utils.py, app/storage_migrations.py'},
    {'id': 'backup_archive', 'location': 'artifacts/backups/*.zip',
     'format': 'ZIP; manifest.json (sorted keys, compact) {files: [{path, sha256, size}], format_version: 2, '
               'created_at "...Z", data_schema_version: 2, producer: "webssh"}; members under data/',
     'parameters': {'export_excludes': 'keys/, credentials.json, automation-vault.json, deleted_users/, '
                                       'logs/, tmp/, .access-revocations/, .ldap-revocation-fences/',
                    'recovery_snapshot': 'internal rollback; keeps keys, credentials and vault'},
     'source': 'app/backup_manager.py, app/online_backup.py'},
]

# Everything a user or administrator can create or configure.
ENTITIES = [
    ('user account', 'users', True, 'admin, non-admin, locked, ADMIN_USERS, bcrypt limit, legacy Unicode name, deleted (id reused)'),
    ('local password', 'users.password_hash', True, '72-byte UTF-8 boundary'),
    ('LDAP identity', 'ldap_identities', True, 'provisioned account'),
    ('GitHub identity', 'github_identities', True, 'provisioned (managed) and linked (local)'),
    ('OIDC identity', 'oidc_identities', True, 'admin link on a local account'),
    ('GitHub sign-in configuration', 'github_auth_configuration', True, 'disabled, secret stored'),
    ('security feature gate', 'security_feature_states', True, 'passkey, totp, recovery on; oidc, ldap absent'),
    ('TOTP authenticator', 'totp_authenticators', True, 'active'),
    ('TOTP enrollment', 'totp_enrollments', True, 'abandoned, expires after 5 minutes'),
    ('passkey', 'webauthn_credentials', True, 'ES256, RS256, EdDSA synced (counter 0, BE/BS, Unicode name); one deleted'),
    ('recovery codes', 'recovery_codes', True, 'one consumed'),
    ('browser login', 'authentication_sessions + cookies', True, 'valid, revoked, expired variants'),
    ('transient auth state', 'pending_authentications, step_up_*, factor_bootstrap_tokens, '
     'github_oauth_states, oidc_login_states, webauthn_challenges', False, 'short-lived, not user data'),
    ('runtime sessions', 'socket_sessions, ssh_sessions', False, 'live connections only'),
    ('automation schedule', 'automation_schedules', True, 'active and paused'),
    ('admin settings', 'data/app_settings.json', True, 'credentials/automation on, support links off'),
    ('global host key', 'data/known_hosts', True, 'trusted and @revoked'),
    ('session epoch', 'data/session_epoch', True, 'rotated once'),
    ('SSH host profile', 'users/user_N/profiles.json', True, 'password, key, jump, SOCKS, Unicode, 200-char name, minimal, deleted, detected facts'),
    ('jump host', 'users/user_N/jump_hosts.json', True, 'one live, one deleted'),
    ('SOCKS proxy', 'users/user_N/socks_proxies.json', True, 'no auth and password auth, Unicode'),
    ('SMB share', 'users/user_N/smb_shares.json', True, 'with domain, empty domain, deleted'),
    ('SSH private key', 'users/user_N/keys/', True, 'RSA, ECDSA P-256/384/521, Ed25519; OpenSSH and PEM; legacy plaintext; deleted; rejected formats as vectors'),
    ('user host key', 'users/user_N/known_hosts', True, 'three recorded, one deleted'),
    ('user settings', 'users/user_N/settings.json', True, 'customized'),
    ('user command', 'users/user_N/commands.json', True, 'Unicode, deleted'),
    ('command set', 'users/user_N/command_sets.json', True, 'inline, parameterized, library, Unicode, deleted'),
    ('host context', 'users/user_N/host_context.json', True, 'notes, directories, command set reference'),
    ('saved password', 'users/user_N/credentials.json', True, 'assigned, unassigned 4096-byte Unicode, empty username, deleted'),
    ('automation runbook', 'users/user_N/automation.json', True, '2 steps; 20 steps Unicode; deleted'),
    ('automation vault', 'users/user_N/automation-vault.json', True, 'three passwords incl. 4096 bytes'),
    ('automation run history', 'users/user_N/automation-runs.json', True, 'one failed run with output'),
    ('deleted account data', 'data/deleted_users/user_N_<hex>/', True, 'quarantined by delete_user_account'),
    ('audit and app logs', 'data/logs/*.log[.N]', True, 'current files only, no rotation'),
    ('legacy single-user stores', 'data/profiles.json, data/keys/, data/commands/', False, 'pre-multi-user layout'),
    ('access revocation queue', 'data/.access-revocations/', False, 'runtime queue, excluded from backups'),
    ('LDAP revocation fences', 'data/.ldap-revocation-fences/', False, 'runtime state, excluded from backups'),
    ('transfer temp files', 'TRANSFER_TEMP_DIR (data/tmp)', False, 'transient'),
    ('backup operations', 'BACKUP_TEMP_DIR', False, 'transient; archives themselves are in artifacts/backups'),
    ('profile export file', 'download (app/profile_exchange.py)', False, 'not stored in DATA_DIR'),
    ('deployment configuration', 'environment / .env', True, 'manifest.environment'),
]
