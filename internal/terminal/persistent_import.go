package terminal

import (
	"context"
	"fmt"

	"github.com/bifrost0x/webssh/internal/store"
)

// ImportedPersistent is a persistent tmux session as the migration wrote
// it: the row id it kept from the Python database and the row.
type ImportedPersistent struct {
	ID  int64
	Row PersistentRow
}

// ImportPersistentAt writes one persistent tmux session read from the
// Python database under its row id there (ssh_sessions.id), detached.
// Keeping the id keeps the order of the sessions and lets the migration
// verify every row against its source. The migration (D2) calls it inside
// its write transaction, before the server has written any row.
func ImportPersistentAt(ctx context.Context, tx *store.Tx, id int64, r PersistentRow) error {
	if id <= 0 {
		return fmt.Errorf("terminal: import persistent session %q: row id %d", r.SessionID, id)
	}
	r.Connected = false
	_, err := tx.ExecContext(ctx, `INSERT INTO terminal_persistent_sessions (id, `+persistentColumns+`)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, r.SessionID, r.UserID, r.Host, r.Port, r.Username, r.KeyID, r.AuthType,
		r.TmuxSessionName, r.DisplayName, r.JumpHostID, r.SOCKSProxyID, r.ViaSOCKS, r.ProfileID,
		r.ViaJump, r.ReconnectRouteKnown, r.Connected, r.CreatedAt, r.LastActivity)
	if err != nil {
		return fmt.Errorf("terminal: import persistent session %q: %w", r.SessionID, err)
	}
	return nil
}

// ImportedPersistentTx reads back every stored persistent tmux session
// with its row id, ordered by it, for the verification of the migration.
func ImportedPersistentTx(ctx context.Context, tx *store.Tx) ([]ImportedPersistent, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, `+persistentColumns+` FROM terminal_persistent_sessions ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ImportedPersistent
	for rows.Next() {
		var p ImportedPersistent
		r := &p.Row
		if err := rows.Scan(&p.ID, &r.SessionID, &r.UserID, &r.Host, &r.Port, &r.Username, &r.KeyID, &r.AuthType,
			&r.TmuxSessionName, &r.DisplayName, &r.JumpHostID, &r.SOCKSProxyID, &r.ViaSOCKS, &r.ProfileID,
			&r.ViaJump, &r.ReconnectRouteKnown, &r.Connected, &r.CreatedAt, &r.LastActivity); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
