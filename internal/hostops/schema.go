package hostops

import "github.com/bifrost0x/webssh/internal/store"

// Schema is the host-operations schema.
func Schema() store.Schema {
	return store.Schema{Owner: "hostops", Migrations: []store.Migration{
		{Version: 1, SQL: notesTableSQL},
	}}
}
