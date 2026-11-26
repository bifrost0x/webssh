package hostkey

import "github.com/bifrost0x/webssh/internal/store"

// Schema is the host-key schema. A trust store is kept as the raw bytes of
// its known_hosts file, one row for the global file (user_id 0) and one per
// user: entry IDs are digests of raw lines, unrelated lines must survive
// every change byte for byte, and one invalid line makes the whole file
// unusable, exactly as with the files of the Python release.
func Schema() store.Schema {
	return store.Schema{Owner: "hostkey", Migrations: []store.Migration{{
		Version: 1,
		SQL: `CREATE TABLE hostkey_files (
	scope TEXT NOT NULL CHECK (scope IN ('global', 'user')),
	user_id INTEGER NOT NULL CHECK ((scope = 'global' AND user_id = 0) OR (scope = 'user' AND user_id > 0)),
	raw BLOB NOT NULL,
	modified_us INTEGER NOT NULL,
	PRIMARY KEY (scope, user_id)
) STRICT`,
	}}}
}
