package totp

import "github.com/bifrost0x/webssh/internal/store"

// Schema returns the TOTP tables. Secrets are sealed with the keyring
// (purpose totp) and bound to table, id and user. Tokens and session
// bindings are stored as SHA-256 only. Times are microseconds since the
// Unix epoch (UTC).
func Schema() store.Schema {
	return store.Schema{Owner: "totp", Migrations: []store.Migration{{Version: 1, SQL: `
CREATE TABLE totp_authenticators (
	id INTEGER PRIMARY KEY,
	user_id INTEGER NOT NULL CHECK (user_id > 0),
	label TEXT NOT NULL,
	sealed_secret BLOB NOT NULL,
	active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
	last_accepted_step INTEGER CHECK (last_accepted_step >= 0),
	created_at INTEGER NOT NULL,
	activated_at INTEGER,
	last_used_at INTEGER
) STRICT;
CREATE INDEX totp_authenticators_user ON totp_authenticators (user_id);
CREATE TABLE totp_enrollments (
	id INTEGER PRIMARY KEY,
	token_hash BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32),
	user_id INTEGER NOT NULL CHECK (user_id > 0),
	binding_hash BLOB NOT NULL CHECK (length(binding_hash) = 32),
	sealed_secret BLOB NOT NULL,
	label TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL
) STRICT;
CREATE INDEX totp_enrollments_user ON totp_enrollments (user_id);
`}}}
}
