package commands

import (
	"context"
	"encoding/json/jsontext"
	"fmt"

	"github.com/bifrost0x/webssh/internal/store"
)

// Schema is the store of the commands area (owner "commands"): one row
// per command and per command set of a user, in the order of the Python
// store, with the record as Python stored it (E26, E27). Unknown members
// are kept; the rules of the Python release read the record itself.
func Schema() store.Schema {
	return store.Schema{Owner: "commands", Migrations: []store.Migration{{Version: 1, SQL: schemaSQL}}}
}

const schemaSQL = `CREATE TABLE commands_user (
	user_id INTEGER NOT NULL CHECK (user_id > 0),
	position INTEGER NOT NULL CHECK (position >= 0),
	id TEXT NOT NULL,
	record TEXT NOT NULL CHECK (json_valid(record) AND json_type(record) = 'object'),
	PRIMARY KEY (user_id, position)
) STRICT;
CREATE TABLE commands_sets (
	user_id INTEGER NOT NULL CHECK (user_id > 0),
	position INTEGER NOT NULL CHECK (position >= 0),
	id TEXT NOT NULL,
	record TEXT NOT NULL CHECK (json_valid(record) AND json_type(record) = 'object'),
	PRIMARY KEY (user_id, position)
) STRICT`

// table is one of the two stores.
type table string

const (
	commandTable table = "commands_user"
	setTable     table = "commands_sets"
)

// load returns the records of a user in order.
func load(ctx context.Context, tx *store.Tx, t table, userID int64) ([]jsontext.Value, error) {
	// #nosec G202 -- t is one of two constants.
	rows, err := tx.QueryContext(ctx, `SELECT record FROM `+string(t)+` WHERE user_id = ? ORDER BY position`, userID)
	if err != nil {
		return nil, fmt.Errorf("commands: read %s: %w", t, err)
	}
	defer rows.Close()
	var out []jsontext.Value
	for rows.Next() {
		var rec string
		if err := rows.Scan(&rec); err != nil {
			return nil, fmt.Errorf("commands: read %s: %w", t, err)
		}
		out = append(out, jsontext.Value(rec))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("commands: read %s: %w", t, err)
	}
	return out, nil
}

// replace stores the records of a user in this order.
func replace(ctx context.Context, tx *store.Tx, t table, userID int64, records []jsontext.Value) error {
	// #nosec G202 -- t is one of two constants.
	if _, err := tx.ExecContext(ctx, `DELETE FROM `+string(t)+` WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("commands: write %s: %w", t, err)
	}
	for i, rec := range records {
		id, _ := recordID(rec)
		// #nosec G202 -- t is one of two constants.
		if _, err := tx.ExecContext(ctx, `INSERT INTO `+string(t)+` (user_id, position, id, record) VALUES (?, ?, ?, ?)`,
			userID, i, id, string(rec)); err != nil {
			return fmt.Errorf("commands: write %s: %w", t, err)
		}
	}
	return nil
}

// recordID is the text id of a stored record ("" when it has none).
func recordID(rec jsontext.Value) (string, bool) {
	m, ok := decode(rec)
	if !ok {
		return "", false
	}
	obj, _ := m.(map[string]any)
	id, ok := obj["id"].(string)
	return id, ok
}
