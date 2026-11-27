package legacy

import (
	"context"
	"fmt"

	"github.com/bifrost0x/webssh/internal/store"
)

// Installation is the migration state of a live installation: the
// migration record, the purge entry and where the keyring material lives.
// A restored database takes it over (migration specification, 5.6 step
// 6): the live legacy source is not touched, so the recorded digest stays
// valid, and the restore never moves the installation into another state
// of section 5.1. The restore itself is recorded in the restore journal.
type Installation struct {
	record, purge [][]any
	materialInGo  bool
}

// migrationTables are the tables of owner "migrate" a restore replaces,
// with the rows of the live installation.
var migrationTables = []string{"migrate_record", "migrate_purge"}

// ReadInstallation reads the migration state of the live database db
// (nil: there is none, a new installation).
func ReadInstallation(ctx context.Context, db *store.DB) (Installation, error) {
	var in Installation
	if db == nil {
		return in, nil
	}
	err := db.Read(ctx, func(tx *store.Tx) error {
		var err error
		if in.record, err = tableRows(ctx, tx, "migrate_record"); err != nil {
			return err
		}
		if in.purge, err = tableRows(ctx, tx, "migrate_purge"); err != nil {
			return err
		}
		var flag int
		if err := tx.QueryRowContext(ctx, `SELECT coalesce(max(material_in_go), 0) FROM migrate_keyring`).Scan(&flag); err != nil {
			return fmt.Errorf("legacy: read the keyring row: %w", err)
		}
		in.materialInGo = flag == 1
		return nil
	})
	return in, err
}

// CarryTx replaces the migration state of a restored database with the
// installation's, and records keyID, the key identifier its sealed
// records now belong to. tx belongs to the restored database, which has
// this build's schemas.
func (in Installation) CarryTx(ctx context.Context, tx *store.Tx, keyID string) error {
	for i, table := range migrationTables {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+table); err != nil { // #nosec G202 -- fixed table names
			return fmt.Errorf("legacy: clear %s: %w", table, err)
		}
		rows := in.record
		if i == 1 {
			rows = in.purge
		}
		for _, row := range rows {
			marks := "?"
			for range len(row) - 1 {
				marks += ", ?"
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO `+table+` VALUES (`+marks+`)`, row...); err != nil { // #nosec G202 -- fixed table names
				return fmt.Errorf("legacy: carry %s: %w", table, err)
			}
		}
	}
	flag := 0
	if in.materialInGo {
		flag = 1
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO migrate_keyring (id, key_id, material_in_go) VALUES (1, ?, ?)
ON CONFLICT (id) DO UPDATE SET key_id = excluded.key_id, material_in_go = excluded.material_in_go`, keyID, flag); err != nil {
		return fmt.Errorf("legacy: store the key identifier: %w", err)
	}
	return nil
}

func tableRows(ctx context.Context, tx *store.Tx, table string) ([][]any, error) {
	rows, err := tx.QueryContext(ctx, `SELECT * FROM `+table) // #nosec G202 -- fixed table names
	if err != nil {
		return nil, fmt.Errorf("legacy: read %s: %w", table, err)
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out [][]any
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, fmt.Errorf("legacy: read %s: %w", table, err)
		}
		out = append(out, vals)
	}
	return out, rows.Err()
}
