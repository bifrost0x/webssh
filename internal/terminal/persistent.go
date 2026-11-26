package terminal

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/bifrost0x/webssh/internal/store"
)

// Schema is the terminal schema: the persistent tmux sessions
// (terminal_persistent_sessions, migration specification A01, D-09). A row
// names a tmux session on a host that outlives its SSH connection, so the
// user can reattach to it. The columns are those of the Python release's
// ssh_sessions for persistent rows. tmux_session_name is kept byte for
// byte; created_at and last_activity hold the naive UTC text of that
// release. connected is informational: a row counts as detached whenever
// no live session of the process has its session_id.
func Schema() store.Schema {
	return store.Schema{Owner: "terminal", Migrations: []store.Migration{{
		Version: 1,
		SQL: `CREATE TABLE terminal_persistent_sessions (
	id INTEGER PRIMARY KEY,
	session_id TEXT NOT NULL UNIQUE,
	user_id INTEGER NOT NULL CHECK (user_id > 0),
	host TEXT NOT NULL,
	port INTEGER NOT NULL,
	username TEXT NOT NULL,
	key_id TEXT,
	auth_type TEXT NOT NULL,
	tmux_session_name TEXT NOT NULL CHECK (length(CAST(tmux_session_name AS BLOB)) BETWEEN 1 AND 256),
	display_name TEXT,
	jump_host_id TEXT,
	socks_proxy_id TEXT,
	via_socks INTEGER NOT NULL CHECK (via_socks IN (0, 1)),
	profile_id TEXT,
	via_jump TEXT,
	reconnect_route_known INTEGER NOT NULL CHECK (reconnect_route_known IN (0, 1)),
	connected INTEGER NOT NULL CHECK (connected IN (0, 1)),
	created_at TEXT,
	last_activity TEXT
) STRICT;
CREATE INDEX terminal_persistent_sessions_by_user ON terminal_persistent_sessions (user_id, tmux_session_name);`,
	}}}
}

// PersistentRow is one persistent tmux session. Optional text columns are
// NullString so a migrated NULL stays NULL.
type PersistentRow struct {
	SessionID           string
	UserID              int64
	Host                string
	Port                int64
	Username            string
	KeyID               sql.NullString
	AuthType            string
	TmuxSessionName     string
	DisplayName         sql.NullString
	JumpHostID          sql.NullString
	SOCKSProxyID        sql.NullString
	ViaSOCKS            bool
	ProfileID           sql.NullString
	ViaJump             sql.NullString
	ReconnectRouteKnown bool
	Connected           bool
	CreatedAt           sql.NullString
	LastActivity        sql.NullString
}

// pyTime is the text SQLAlchemy stored for a naive UTC DateTime.
func pyTime(t time.Time) sql.NullString {
	return sql.NullString{String: t.UTC().Format("2006-01-02 15:04:05.000000"), Valid: true}
}

func nullable(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

const persistentColumns = `session_id, user_id, host, port, username, key_id, auth_type,
	tmux_session_name, display_name, jump_host_id, socks_proxy_id, via_socks, profile_id,
	via_jump, reconnect_route_known, connected, created_at, last_activity`

func insertRow(ctx context.Context, tx *store.Tx, r PersistentRow) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO terminal_persistent_sessions (`+persistentColumns+`)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.SessionID, r.UserID, r.Host, r.Port, r.Username, r.KeyID, r.AuthType,
		r.TmuxSessionName, r.DisplayName, r.JumpHostID, r.SOCKSProxyID, r.ViaSOCKS, r.ProfileID,
		r.ViaJump, r.ReconnectRouteKnown, r.Connected, r.CreatedAt, r.LastActivity)
	return err
}

func scanRows(rows *sql.Rows) ([]PersistentRow, error) {
	defer rows.Close()
	var out []PersistentRow
	for rows.Next() {
		var r PersistentRow
		if err := rows.Scan(&r.SessionID, &r.UserID, &r.Host, &r.Port, &r.Username, &r.KeyID, &r.AuthType,
			&r.TmuxSessionName, &r.DisplayName, &r.JumpHostID, &r.SOCKSProxyID, &r.ViaSOCKS, &r.ProfileID,
			&r.ViaJump, &r.ReconnectRouteKnown, &r.Connected, &r.CreatedAt, &r.LastActivity); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ImportPersistent writes the persistent tmux sessions read from the
// Python database in the given order (ssh_sessions by row id) as
// detached sessions. Names and every other value are kept as read. The
// migration (D2) calls it inside its write transaction.
func ImportPersistent(ctx context.Context, tx *store.Tx, rows []PersistentRow) error {
	for i, r := range rows {
		r.Connected = false
		if err := insertRow(ctx, tx, r); err != nil {
			return fmt.Errorf("terminal: import persistent session %d of %d: %w", i+1, len(rows), err)
		}
	}
	return nil
}

// persistent is the table of persistent tmux sessions.
type persistent struct{ db *store.DB }

func (p persistent) query(ctx context.Context, where string, args ...any) ([]PersistentRow, error) {
	var out []PersistentRow
	err := p.db.Read(ctx, func(tx *store.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT `+persistentColumns+` FROM terminal_persistent_sessions WHERE `+where+` ORDER BY id`, args...) // #nosec G202 -- constant clauses
		if err != nil {
			return err
		}
		out, err = scanRows(rows)
		return err
	})
	return out, err
}

// ofUser lists every persistent session of owner, oldest first.
func (p persistent) ofUser(ctx context.Context, owner int64) ([]PersistentRow, error) {
	return p.query(ctx, `user_id = ?`, owner)
}

// byName finds the first persistent session of owner with exactly name.
func (p persistent) byName(ctx context.Context, owner int64, name string) (PersistentRow, bool, error) {
	rows, err := p.query(ctx, `user_id = ? AND tmux_session_name = ?`, owner, name)
	if err != nil || len(rows) == 0 {
		return PersistentRow{}, false, err
	}
	return rows[0], true, nil
}

// record stores the row of a new tmux session. For a reattach it first
// removes the detached row of the same tmux session on the same host, so
// a reload does not offer it twice (Python: "Cleaned up old persistent
// session").
func (p persistent) record(ctx context.Context, r PersistentRow, reattached bool) error {
	return p.db.Write(ctx, func(tx *store.Tx) error {
		if reattached {
			if _, err := tx.ExecContext(ctx, `DELETE FROM terminal_persistent_sessions
	WHERE id = (SELECT id FROM terminal_persistent_sessions
		WHERE user_id = ? AND host = ? AND port = ? AND tmux_session_name = ? AND connected = 0 ORDER BY id LIMIT 1)`,
				r.UserID, r.Host, r.Port, r.TmuxSessionName); err != nil {
				return err
			}
		}
		return insertRow(ctx, tx, r)
	})
}

// detached marks the session's row as not connected.
func (p persistent) detached(ctx context.Context, sessionID string, at time.Time) error {
	return p.db.Write(ctx, func(tx *store.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE terminal_persistent_sessions SET connected = 0, last_activity = ? WHERE session_id = ?`,
			pyTime(at), sessionID)
		return err
	})
}

// remove deletes the session's row.
func (p persistent) remove(ctx context.Context, sessionID string) error {
	return p.db.Write(ctx, func(tx *store.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM terminal_persistent_sessions WHERE session_id = ?`, sessionID)
		return err
	})
}

// removeUser deletes every row of owner and returns them.
func (p persistent) removeUser(ctx context.Context, owner int64) ([]PersistentRow, error) {
	var out []PersistentRow
	err := p.db.Write(ctx, func(tx *store.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT `+persistentColumns+` FROM terminal_persistent_sessions WHERE user_id = ? ORDER BY id`, owner)
		if err != nil {
			return err
		}
		if out, err = scanRows(rows); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM terminal_persistent_sessions WHERE user_id = ?`, owner)
		return err
	})
	return out, err
}

// rename sets the display name of owner's row; false when there is none.
func (p persistent) rename(ctx context.Context, owner int64, sessionID, name string) (bool, error) {
	var n int64
	err := p.db.Write(ctx, func(tx *store.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE terminal_persistent_sessions SET display_name = ? WHERE user_id = ? AND session_id = ?`,
			nullable(name), owner, sessionID)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	return n > 0, err
}
