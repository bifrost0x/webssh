package legacy

import (
	"context"
	"testing"

	"github.com/bifrost0x/webssh/internal/store"
)

// testPersistent stands in for the adapter of internal/terminal (D6).
type testPersistent struct{}

func (*testPersistent) Schema() store.Schema {
	return store.Schema{Owner: "terminal", Migrations: []store.Migration{{Version: 1, SQL: `CREATE TABLE terminal_test_persistent (
	row_id INTEGER PRIMARY KEY, session_id TEXT NOT NULL, user_id INTEGER NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL,
	username TEXT NOT NULL, key_id TEXT, auth_type TEXT NOT NULL, tmux_session_name TEXT NOT NULL, display_name TEXT,
	jump_host_id TEXT, socks_proxy_id TEXT, via_socks INTEGER NOT NULL, profile_id TEXT, via_jump TEXT,
	reconnect_route_known INTEGER NOT NULL, created_at TEXT, last_activity TEXT, connected INTEGER NOT NULL) STRICT;`}}}
}

func (*testPersistent) ImportPersistentTx(ctx context.Context, tx *store.Tx, p PersistentSession) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO terminal_test_persistent VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
		p.RowID, p.SessionID, p.UserID, p.Host, p.Port, p.Username, p.KeyID, p.AuthType, p.TmuxSessionName, p.DisplayName,
		p.JumpHostID, p.SOCKSProxyID, p.ViaSOCKS, p.ProfileID, p.ViaJump, p.ReconnectRouteKnown, p.CreatedAt, p.LastActivity)
	return err
}

func (*testPersistent) PersistentTx(ctx context.Context, tx *store.Tx) ([]PersistentSession, error) {
	rows, err := tx.QueryContext(ctx, `SELECT row_id, session_id, user_id, host, port, username, key_id, auth_type, tmux_session_name,
		display_name, jump_host_id, socks_proxy_id, via_socks, profile_id, via_jump, reconnect_route_known, created_at, last_activity
		FROM terminal_test_persistent ORDER BY row_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PersistentSession
	for rows.Next() {
		var p PersistentSession
		if err := rows.Scan(&p.RowID, &p.SessionID, &p.UserID, &p.Host, &p.Port, &p.Username, &p.KeyID, &p.AuthType,
			&p.TmuxSessionName, &p.DisplayName, &p.JumpHostID, &p.SOCKSProxyID, &p.ViaSOCKS, &p.ProfileID, &p.ViaJump,
			&p.ReconnectRouteKnown, &p.CreatedAt, &p.LastActivity); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// A01: the persistent tmux sessions of the extended data set come back
// with their tmux and display names byte for byte (I-11); without a
// store they stay pending for D6 with their number.
func TestM1PersistentSessions(t *testing.T) {
	t.Parallel()
	fx := legacyFixture(t)
	dir := extractLegacy(t, "datadir-extended.tar")
	m := migrateM1(t, dir, fx.SecretKey.Value, M1{Persistent: &testPersistent{}})
	var got []PersistentSession
	err := m.db.Read(t.Context(), func(tx *store.Tx) error {
		var err error
		got, err = (&testPersistent{}).PersistentTx(t.Context(), tx)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]*string{}
	for _, p := range fx.Values.Extended.PersistentSessions {
		if p.IsPersistent && p.Tmux != nil {
			want[*p.Tmux] = p.DisplayName
		}
	}
	if len(got) != len(want) || len(got) == 0 {
		t.Fatalf("sessions %d, want %d", len(got), len(want))
	}
	for _, p := range got {
		display, ok := want[p.TmuxSessionName]
		if !ok || (display == nil) == p.DisplayName.Valid || (display != nil && *display != p.DisplayName.String) {
			t.Errorf("session %q: display %v", p.TmuxSessionName, p.DisplayName)
		}
	}
	dir2 := extractLegacy(t, "datadir-extended.tar")
	m2 := migrateM1(t, dir2, fx.SecretKey.Value, M1{})
	for _, p := range m2.report.Pending {
		if p.Entity == "A01" && (p.Phase != "D6" || p.Count != len(want)) {
			t.Errorf("pending A01 %+v", p)
		}
	}
}
