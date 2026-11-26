package github

import "github.com/bifrost0x/webssh/internal/store"

// Schema returns the package's tables. Times are microseconds since the
// Unix epoch (UTC).
//
//   - authgithub_config is the single configuration row (E06); the client
//     secret is sealed with keyring.GitHubClientSecret, allowed_orgs is the
//     JSON text as stored (allowed_orgs_json), redirect_uri is kept byte
//     for byte (I-03).
//   - authgithub_identities binds the numeric GitHub user id to one
//     account (E04); provisioned is provisioned_by_github.
//   - authgithub_flights are the OAuth redirects in progress
//     (github_oauth_states): the state and the browser binding only as MAC.
func Schema() store.Schema {
	return store.Schema{Owner: Owner, Migrations: []store.Migration{{Version: 1, SQL: `
CREATE TABLE authgithub_config (
	singleton         INTEGER PRIMARY KEY CHECK (singleton = 1),
	enabled           INTEGER NOT NULL CHECK (enabled IN (0, 1)),
	client_id         TEXT NOT NULL,
	client_secret     BLOB,
	redirect_uri      TEXT NOT NULL,
	auto_provision    INTEGER NOT NULL CHECK (auto_provision IN (0, 1)),
	allowed_orgs      TEXT NOT NULL,
	generation        INTEGER NOT NULL,
	updated_by        INTEGER,
	updated_us        INTEGER NOT NULL,
	secret_updated_us INTEGER
) STRICT;
CREATE TABLE authgithub_identities (
	id               INTEGER PRIMARY KEY,
	user_id          INTEGER NOT NULL UNIQUE CHECK (user_id > 0),
	github_user_id   TEXT NOT NULL UNIQUE,
	login            TEXT NOT NULL,
	display_name     TEXT,
	provisioned      INTEGER NOT NULL CHECK (provisioned IN (0, 1)),
	created_us       INTEGER NOT NULL,
	updated_us       INTEGER NOT NULL,
	last_verified_us INTEGER
) STRICT;
CREATE TABLE authgithub_flights (
	state_mac         BLOB PRIMARY KEY,
	binding_mac       BLOB NOT NULL,
	purpose           TEXT NOT NULL CHECK (purpose IN ('login', 'link')),
	verifier          TEXT NOT NULL,
	user_id           INTEGER,
	auth_generation   INTEGER,
	session_id        TEXT,
	continuation      TEXT NOT NULL,
	config_generation INTEGER NOT NULL,
	issued_us         INTEGER NOT NULL,
	expires_us        INTEGER NOT NULL
) STRICT;
CREATE INDEX authgithub_flights_expiry ON authgithub_flights (expires_us);`}}}
}
