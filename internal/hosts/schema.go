package hosts

import "github.com/bifrost0x/webssh/internal/store"

// Schema is the hosts schema (migration spec E19, E20, E21, A06, A11).
//
// A saved host, jump host or SOCKS5 proxy is one row per record, in the
// order of the user's list (position). Every field the Python release
// knows has a column of its own holding the field's JSON value, or NULL
// when the record does not have the field: legacy values keep their exact
// type and integers of any size survive. Members Python tolerated but does
// not name go to legacy_extra; field_order is the member order of the
// record, so a saved host is sent exactly as it was stored and a field
// this release does not know survives every change. Record IDs are not
// unique keys: the Python stores never enforced that, and the first record
// with an ID wins, as there.
func Schema() store.Schema {
	return store.Schema{Owner: "hosts", Migrations: []store.Migration{{
		Version: 1,
		SQL: `CREATE TABLE hosts_profiles (
	user_id INTEGER NOT NULL CHECK (user_id > 0),
	position INTEGER NOT NULL CHECK (position >= 0),
	field_order TEXT NOT NULL,
	legacy_extra TEXT NOT NULL,
	"id" TEXT, "name" TEXT, "host" TEXT, "port" TEXT, "username" TEXT,
	"auth_type" TEXT, "key_id" TEXT, "jump_host_id" TEXT, "socks_proxy_id" TEXT,
	"startup_mode" TEXT, "startup_commands" TEXT, "command_id" TEXT,
	"command_set_id" TEXT, "parameters_override" TEXT, "use_tmux" TEXT,
	"herdr" TEXT, "use_herdr" TEXT, "group" TEXT, "favorite" TEXT,
	"created_at" TEXT, "updated_at" TEXT, "sort_order" TEXT,
	"platform_icon" TEXT, "detected_platform" TEXT, "greeting_platform" TEXT,
	"detected_services" TEXT, "services_checked_at" TEXT,
	"detected_maintenance" TEXT, "detected_family" TEXT, "detected_os_id" TEXT,
	"detected_os_version" TEXT, "detected_virt" TEXT,
	"detected_container_access" TEXT, "detected_guests" TEXT,
	"detected_graphical" TEXT, "detection_state" TEXT,
	"platform_checked_at" TEXT, "role_override" TEXT,
	"authenticated_greeting" TEXT,
	PRIMARY KEY (user_id, position)
) STRICT;
CREATE INDEX hosts_profiles_by_id ON hosts_profiles (user_id, "id");
CREATE TABLE hosts_jump_hosts (
	user_id INTEGER NOT NULL CHECK (user_id > 0),
	position INTEGER NOT NULL CHECK (position >= 0),
	field_order TEXT NOT NULL,
	legacy_extra TEXT NOT NULL,
	"id" TEXT, "name" TEXT, "host" TEXT, "port" TEXT, "username" TEXT,
	"auth_type" TEXT, "key_id" TEXT, "created_at" TEXT,
	PRIMARY KEY (user_id, position)
) STRICT;
CREATE TABLE hosts_socks_proxies (
	user_id INTEGER NOT NULL CHECK (user_id > 0),
	position INTEGER NOT NULL CHECK (position >= 0),
	field_order TEXT NOT NULL,
	legacy_extra TEXT NOT NULL,
	"id" TEXT, "name" TEXT, "host" TEXT, "port" TEXT, "username" TEXT,
	"auth_type" TEXT, "remote_dns" TEXT, "created_at" TEXT,
	PRIMARY KEY (user_id, position)
) STRICT;
CREATE TABLE hosts_workspace_presets (
	user_id INTEGER PRIMARY KEY CHECK (user_id > 0),
	presets TEXT NOT NULL
) STRICT`,
	}}}
}

// Column sets of the record tables, in table order. The profile fields are
// _PROFILE_FIELDS of app/profile_manager.py, the SOCKS fields
// _SOCKS_PROXY_FIELDS of app/socks_proxy_manager.py, the jump-host fields
// those add_jump_host writes.
var (
	profileFields = []string{
		"id", "name", "host", "port", "username", "auth_type", "key_id",
		"jump_host_id", "socks_proxy_id", "startup_mode", "startup_commands",
		"command_id", "command_set_id", "parameters_override", "use_tmux",
		"herdr", "use_herdr", "group", "favorite", "created_at", "updated_at",
		"sort_order", "platform_icon", "detected_platform", "greeting_platform",
		"detected_services", "services_checked_at", "detected_maintenance",
		"detected_family", "detected_os_id", "detected_os_version",
		"detected_virt", "detected_container_access", "detected_guests",
		"detected_graphical", "detection_state", "platform_checked_at",
		"role_override", "authenticated_greeting",
	}
	jumpFields  = []string{"id", "name", "host", "port", "username", "auth_type", "key_id", "created_at"}
	socksFields = []string{"id", "name", "host", "port", "username", "auth_type", "remote_dns", "created_at"}
)

// table is one record table and its known fields.
type table struct {
	name   string
	fields []string
}

var (
	profileTable = table{"hosts_profiles", profileFields}
	jumpTable    = table{"hosts_jump_hosts", jumpFields}
	socksTable   = table{"hosts_socks_proxies", socksFields}
)
