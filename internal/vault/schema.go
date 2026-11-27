package vault

import "github.com/bifrost0x/webssh/internal/store"

// Schema is the vault schema: the users' SSH private keys (version 1) and
// their saved passwords with the legacy automation vault (version 2).
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
	id TEXT NOT NULL,
	user_id INTEGER NOT NULL CHECK (user_id > 0),
	seq INTEGER NOT NULL,
	name TEXT NOT NULL,
	key_type TEXT NOT NULL,
	public_key TEXT NOT NULL,
	fingerprint_sha256 TEXT NOT NULL,
	private_key BLOB NOT NULL,
	uploaded_at TEXT NOT NULL,
	state TEXT NOT NULL CHECK (state IN ('usable', 'unsupported')),
	PRIMARY KEY (user_id, id),
	UNIQUE (user_id, seq)
) STRICT`,
	}, {
		Version: 2,
		SQL:     credentialsSQL,
	}}}
}

// credentialsSQL holds the saved passwords (credentials.json of the Python
// release) and the legacy automation vault.
//
// vault_credentials: seq keeps the order of the Python document, then
// creation order. secret is the password sealed with keyring.Credential.
// updated_at is the text the page shows, kept verbatim for migrated
// records. vault_credential_assignments binds a resource id ("<id>",
// "jump:<id>", "socks:<id>", "smb:<id>") to one credential with the
// fingerprint of the target the user confirmed; resources are not
// referenced by a foreign key because they belong to other owners.
// vault_credential_imports lists the legacy vault documents already
// imported (digest of the document, as Python recorded it).
// vault_legacy_automation keeps automation-vault.json byte for byte
// (decision D-06): only the user's passphrase opens it.
const credentialsSQL = `CREATE TABLE vault_credentials (
	user_id INTEGER NOT NULL CHECK (user_id > 0),
	id TEXT NOT NULL,
	seq INTEGER NOT NULL,
	name TEXT NOT NULL,
	username TEXT NOT NULL,
	version TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	secret BLOB NOT NULL,
	PRIMARY KEY (user_id, id),
	UNIQUE (user_id, seq)
) STRICT;
CREATE TABLE vault_credential_assignments (
	user_id INTEGER NOT NULL CHECK (user_id > 0),
	resource_id TEXT NOT NULL,
	seq INTEGER NOT NULL,
	credential_id TEXT NOT NULL,
	fingerprint TEXT NOT NULL,
	generation TEXT NOT NULL,
	PRIMARY KEY (user_id, resource_id),
	UNIQUE (user_id, seq),
	FOREIGN KEY (user_id, credential_id) REFERENCES vault_credentials (user_id, id)
) STRICT;
CREATE TABLE vault_credential_imports (
	user_id INTEGER NOT NULL CHECK (user_id > 0),
	seq INTEGER NOT NULL,
	revision TEXT NOT NULL,
	PRIMARY KEY (user_id, seq)
) STRICT;
CREATE TABLE vault_legacy_automation (
	user_id INTEGER PRIMARY KEY CHECK (user_id > 0),
	version INTEGER NOT NULL CHECK (version IN (1, 2)),
	document BLOB NOT NULL
) STRICT` // #nosec G101 -- table definitions, not a credential
