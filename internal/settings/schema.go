package settings

import "github.com/bifrost0x/webssh/internal/store"

// Schema is the settings schema.
//
// settings_app holds one row per application setting. value is the JSON
// text of the setting. source says where the value came from: "admin"
// (changed through this release), "migrated" (copied from the legacy
// app_settings.json) or "materialised" (derived by the upgrade from the
// legacy behaviour, D-01); rule names the decision behind a materialised
// value and is empty otherwise.
//
// settings_user holds one row per account and key. Keys without a row
// take the default of this release. Rows are not tied to the accounts
// table by a foreign key: the stores of two capabilities stay
// independent, and removing an account removes its rows through
// DeleteUser.
//
// settings_notices holds the one-time notices of an account (notice.go),
// one row per account and notice; acknowledged_us is NULL while the
// notice is pending and the time of the acknowledgement afterwards. It
// is a table of its own so that the account settings, which the
// migration compares with the legacy settings.json, stay as they were.
func Schema() store.Schema {
	return store.Schema{Owner: "settings", Migrations: []store.Migration{{
		Version: 1,
		SQL: `CREATE TABLE settings_app (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL CHECK (json_valid(value)),
	source TEXT NOT NULL CHECK (source IN ('admin', 'migrated', 'materialised')),
	rule TEXT NOT NULL DEFAULT '' CHECK ((source = 'materialised') = (rule <> '')),
	updated_us INTEGER NOT NULL
) STRICT;
CREATE TABLE settings_user (
	user_id INTEGER NOT NULL CHECK (user_id > 0),
	key TEXT NOT NULL,
	value TEXT NOT NULL CHECK (json_valid(value)),
	PRIMARY KEY (user_id, key)
) STRICT`,
	}, {
		Version: 2,
		SQL: `CREATE TABLE settings_notices (
	user_id INTEGER NOT NULL CHECK (user_id > 0),
	notice TEXT NOT NULL CHECK (length(notice) BETWEEN 1 AND 64),
	acknowledged_us INTEGER CHECK (acknowledged_us > 0),
	PRIMARY KEY (user_id, notice)
) STRICT`,
	}}}
}
