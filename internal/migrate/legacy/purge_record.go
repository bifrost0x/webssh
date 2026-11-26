package legacy

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	"fmt"

	"github.com/bifrost0x/webssh/internal/store"
)

// purgeEntry is the row of migrate_purge.
type purgeEntry struct {
	InProgress  bool
	Files       []string // legacy paths relative to DATA_DIR, POSIX form
	Backup      string   // the verified backup, "" with --skip-backup
	StartedAt   string
	CompletedAt string
}

// readPurge returns the purge entry, or nil when there is none or the
// database predates the table.
func readPurge(ctx context.Context, q queryer) (*purgeEntry, error) {
	var has int
	if err := q.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'migrate_purge'`).Scan(&has); err != nil {
		return nil, fmt.Errorf("legacy: read the purge entry: %w", err)
	}
	if has == 0 {
		return nil, nil
	}
	var e purgeEntry
	var files string
	err := q.QueryRowContext(ctx, `SELECT in_progress, files, backup, started_at, completed_at FROM migrate_purge WHERE id = 1`).
		Scan(&e.InProgress, &files, &e.Backup, &e.StartedAt, &e.CompletedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("legacy: read the purge entry: %w", err)
	}
	if err := json.Unmarshal([]byte(files), &e.Files); err != nil {
		return nil, fmt.Errorf("legacy: decode the purge entry: %w", err)
	}
	return &e, nil
}

// writePurgeStart records "purge in progress" (section 5.9 step 1).
func writePurgeStart(ctx context.Context, tx *store.Tx, e purgeEntry) error {
	files, err := json.Marshal(e.Files)
	if err != nil {
		return fmt.Errorf("legacy: encode the purge entry: %w", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO migrate_purge (id, in_progress, files, backup, started_at, completed_at)
VALUES (1, 1, ?, ?, ?, '')`, string(files), e.Backup, e.StartedAt)
	if err != nil {
		return fmt.Errorf("legacy: write the purge entry: %w", err)
	}
	return nil
}

// writePurgeDone turns the entry into the purge entry with its backup
// path (section 5.9 step 3); the in-progress state ends in the same
// transaction.
func writePurgeDone(ctx context.Context, tx *store.Tx, completedAt string) error {
	res, err := tx.ExecContext(ctx, `UPDATE migrate_purge SET in_progress = 0, files = '[]', completed_at = ? WHERE id = 1`, completedAt)
	if err == nil {
		if n, _ := res.RowsAffected(); n != 1 {
			err = errors.New("no purge entry")
		}
	}
	if err != nil {
		return fmt.Errorf("legacy: complete the purge entry: %w", err)
	}
	return nil
}

// setMaterialInGo notes that the material lives in go/; it is idempotent.
func setMaterialInGo(ctx context.Context, tx *store.Tx) error {
	if _, err := tx.ExecContext(ctx, `UPDATE migrate_keyring SET material_in_go = 1 WHERE id = 1`); err != nil {
		return fmt.Errorf("legacy: record the material in go/: %w", err)
	}
	return nil
}
