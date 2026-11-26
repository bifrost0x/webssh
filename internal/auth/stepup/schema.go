package stepup

import "github.com/bifrost0x/webssh/internal/store"

// Schema returns the step-up tables. Intent and grant tokens are stored as
// a keyed MAC (keyring purpose step_up_grant), targets as a
// domain-separated SHA-256. Times are microseconds since the Unix epoch.
func Schema() store.Schema {
	return store.Schema{Owner: "stepup", Migrations: []store.Migration{{Version: 1, SQL: `
CREATE TABLE stepup_intents (
	id INTEGER PRIMARY KEY,
	token_mac BLOB NOT NULL UNIQUE,
	user_id INTEGER NOT NULL CHECK (user_id > 0),
	session_id TEXT NOT NULL,
	channel TEXT NOT NULL CHECK (channel IN ('account', 'admin')),
	action TEXT NOT NULL,
	target_hash BLOB NOT NULL CHECK (length(target_hash) = 32),
	required TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL
) STRICT;
CREATE INDEX stepup_intents_session ON stepup_intents (session_id);
CREATE TABLE stepup_grants (
	id INTEGER PRIMARY KEY,
	token_mac BLOB NOT NULL UNIQUE,
	user_id INTEGER NOT NULL CHECK (user_id > 0),
	session_id TEXT NOT NULL,
	action TEXT NOT NULL,
	target_hash BLOB NOT NULL CHECK (length(target_hash) = 32),
	assurance TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL
) STRICT;
CREATE INDEX stepup_grants_session ON stepup_grants (session_id, created_at);
`}}}
}
