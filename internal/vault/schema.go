package vault

import "github.com/bifrost0x/webssh/internal/store"

// Schema is the vault schema of M1: the users' SSH private keys.
//
// seq keeps the order of the key list (the order of keys.json in the
// Python release, then upload order). private_key is the sealed,
// unencrypted private key. state is 'usable' for keys WebSSH can load and
// 'unsupported' for migrated keys it cannot (passphrase-protected or DSA
// material from old releases); those stay listed so the user can replace
// or delete them. public_key (authorized_keys form) and fingerprint_sha256
// are empty for unsupported keys. uploaded_at is the text the client
// shows, kept verbatim for migrated keys. Names and IDs are not
// constrained here: migrated values of older releases stay as they were,
// and the service enforces the rules for new ones.
//
// There is no foreign key to the accounts table: it belongs to another
// owner. Deleting accounts is not part of M1; the phase that adds it
// removes the account's keys with it.
func Schema() store.Schema {
	return store.Schema{Owner: "vault", Migrations: []store.Migration{{
		Version: 1,
		SQL: `CREATE TABLE vault_ssh_keys (
	id TEXT PRIMARY KEY NOT NULL,
	user_id INTEGER NOT NULL CHECK (user_id > 0),
	seq INTEGER NOT NULL,
	name TEXT NOT NULL,
	key_type TEXT NOT NULL,
	public_key TEXT NOT NULL,
	fingerprint_sha256 TEXT NOT NULL,
	private_key BLOB NOT NULL,
	uploaded_at TEXT NOT NULL,
	state TEXT NOT NULL CHECK (state IN ('usable', 'unsupported')),
	UNIQUE (user_id, seq)
) STRICT`,
	}}}
}
