package webauthn

import "github.com/bifrost0x/webssh/internal/store"

// Schema returns the passkey tables. Credential IDs and COSE keys are
// public and kept verbatim (migration entity E10). Challenges are sealed
// with the keyring (purpose webauthn_challenge) and bound to purpose and
// browser binding; bindings are stored as SHA-256 only. Times are
// microseconds since the Unix epoch (UTC).
func Schema() store.Schema {
	return store.Schema{Owner: "webauthn", Migrations: []store.Migration{{Version: 1, SQL: `
CREATE TABLE webauthn_credentials (
	id INTEGER PRIMARY KEY,
	user_id INTEGER NOT NULL CHECK (user_id > 0),
	credential_id BLOB NOT NULL UNIQUE CHECK (length(credential_id) BETWEEN 1 AND 1023),
	public_key BLOB NOT NULL CHECK (length(public_key) > 0),
	sign_count INTEGER NOT NULL DEFAULT 0 CHECK (sign_count BETWEEN 0 AND 4294967295),
	transports TEXT NOT NULL DEFAULT '[]',
	name TEXT NOT NULL,
	backup_eligible INTEGER CHECK (backup_eligible IN (0, 1)),
	backup_state INTEGER CHECK (backup_state IN (0, 1)),
	created_at INTEGER NOT NULL,
	last_used_at INTEGER
) STRICT;
CREATE INDEX webauthn_credentials_user ON webauthn_credentials (user_id);
CREATE TABLE webauthn_challenges (
	id INTEGER PRIMARY KEY,
	purpose TEXT NOT NULL CHECK (purpose IN ('register', 'login', 'mfa_login', 'step_up')),
	binding_hash BLOB NOT NULL CHECK (length(binding_hash) = 32),
	user_id INTEGER CHECK (user_id > 0),
	sealed_challenge BLOB NOT NULL,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	UNIQUE (purpose, binding_hash)
) STRICT;
CREATE INDEX webauthn_challenges_expiry ON webauthn_challenges (expires_at);
CREATE INDEX webauthn_challenges_user ON webauthn_challenges (user_id);
`}}}
}
