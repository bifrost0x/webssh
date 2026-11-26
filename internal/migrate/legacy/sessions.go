package legacy

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// PersistentSession is a row of ssh_sessions that names a persistent tmux
// session (migration specification A01, D-09). The tmux name is copied
// byte for byte: it holds a random part and cannot be derived again.
type PersistentSession struct {
	RowID               int64
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
	CreatedAt           sql.NullString // naive UTC text as stored
	LastActivity        sql.NullString
}

// sessionColumns are read in this order. created_at and last_activity are
// read as stored text.
var sessionColumns = []string{
	"id", "session_id", "user_id", "host", "port", "username", "key_id", "auth_type", "tmux_session_name",
	"display_name", "jump_host_id", "socks_proxy_id", "via_socks", "profile_id", "via_jump",
	"reconnect_route_known", "created_at", "last_activity", "is_persistent",
}

// PersistentSessions returns the persistent tmux sessions of ssh_sessions
// ordered by row id, and the number of other rows, which the migration
// discards (E14). A database without the table has none. Columns an older
// database lacks read with the values Python gives existing rows when it
// adds them. After a restore (Restored) the table counts as empty, because
// Python empties it.
func (s *Source) PersistentSessions(ctx context.Context) (sessions []PersistentSession, discarded int, err error) {
	if !s.schema.HasTable("ssh_sessions") || s.emptiedByRestore("ssh_sessions") {
		return nil, 0, nil
	}
	// Constant identifiers and literals only (columnDefaults).
	query := "SELECT " + s.schema.sessionSelect() + " FROM ssh_sessions ORDER BY id" // #nosec G202 -- constant identifiers and literals
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, 0, fmt.Errorf("legacy: read ssh_sessions: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var p PersistentSession
		var tmux sql.NullString
		var persistent bool
		if err := rows.Scan(&p.RowID, &p.SessionID, &p.UserID, &p.Host, &p.Port, &p.Username, &p.KeyID,
			&p.AuthType, &tmux, &p.DisplayName, &p.JumpHostID, &p.SOCKSProxyID, &p.ViaSOCKS, &p.ProfileID,
			&p.ViaJump, &p.ReconnectRouteKnown, &p.CreatedAt, &p.LastActivity, &persistent); err != nil {
			return nil, 0, fmt.Errorf("legacy: read ssh_sessions: %w", err)
		}
		if !persistent || !tmux.Valid || tmux.String == "" {
			discarded++
			continue
		}
		p.TmuxSessionName = tmux.String
		sessions = append(sessions, p)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("legacy: read ssh_sessions: %w", err)
	}
	return sessions, discarded, nil
}

func (sc Schema) sessionSelect() string {
	exprs := make([]string, len(sessionColumns))
	for i, c := range sessionColumns {
		switch {
		case !sc.HasColumn("ssh_sessions", c) && c == "auth_type" && sc.HasColumn("ssh_sessions", "key_id"):
			exprs[i] = `CASE WHEN key_id IS NOT NULL THEN 'key' ELSE 'password' END`
		case !sc.HasColumn("ssh_sessions", c):
			exprs[i] = columnDefaults["ssh_sessions"][c] // checkKnownColumns guarantees a default
		case c == "created_at" || c == "last_activity":
			exprs[i] = `CAST("` + c + `" AS TEXT)`
		case c == "is_persistent" || c == "via_socks" || c == "reconnect_route_known":
			exprs[i] = `COALESCE("` + c + `", 0) != 0`
		default:
			exprs[i] = `"` + c + `"`
		}
	}
	return strings.Join(exprs, ", ")
}
