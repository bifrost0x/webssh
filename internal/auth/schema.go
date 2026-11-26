package auth

import (
	"strconv"
	"time"

	"github.com/bifrost0x/webssh/internal/store"
)

// Schema returns the tables of this package as one ordered migration
// list: the pending sign-ins of the login flow (a verified primary
// credential that waits for its second factor), then the second-factor
// state (recovery codes and the one-time code backoff). Both parts share
// the owner "auth", so they must stay in this single list; a second
// Schema with the same owner would fail the checksum comparison of
// store.Apply. Times are microseconds since the Unix epoch (UTC).
func Schema() store.Schema {
	return store.Schema{Owner: "auth", Migrations: []store.Migration{
		{Version: 1, SQL: `
CREATE TABLE auth_pending (
	binding_mac     BLOB PRIMARY KEY,
	user_id         INTEGER NOT NULL,
	auth_generation INTEGER NOT NULL,
	primary_method  TEXT NOT NULL,
	assurance       TEXT NOT NULL,
	remember        INTEGER NOT NULL CHECK (remember IN (0, 1)),
	continuation    TEXT NOT NULL,
	created_us      INTEGER NOT NULL,
	expires_us      INTEGER NOT NULL
) STRICT;
CREATE INDEX auth_pending_user ON auth_pending (user_id, created_us);`},
		{Version: 2, SQL: `
CREATE TABLE auth_recovery_codes (
	id INTEGER PRIMARY KEY,
	user_id INTEGER NOT NULL CHECK (user_id > 0),
	algorithm TEXT NOT NULL CHECK (algorithm = 'sha256-webssh-v1'),
	hash BLOB NOT NULL CHECK (length(hash) = 32),
	created_at INTEGER NOT NULL
) STRICT;
CREATE INDEX auth_recovery_codes_user ON auth_recovery_codes (user_id);
CREATE TABLE auth_mfa_throttle (
	user_id INTEGER NOT NULL CHECK (user_id > 0),
	scope TEXT NOT NULL CHECK (scope IN ('login', 'step_up')),
	failures INTEGER NOT NULL CHECK (failures >= 0),
	last_failed_at INTEGER,
	PRIMARY KEY (user_id, scope)
) STRICT, WITHOUT ROWID;
`},
	}}
}

func micros(t time.Time) int64 { return t.UnixMicro() }

func fromMicros(us int64) time.Time { return time.UnixMicro(us).UTC() }

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
