package main

import (
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// reset-password of an account whose browser session already ended
// (expired, or revoked by the user; both keep terminals running) must
// still journal an account-wide revocation, so the running server ends
// the account's SSH terminals as the command says (RS2-01).
func TestResetPasswordWithoutSessionJournalsAccountRevocation(t *testing.T) {
	adminEnv(t)
	if code, _, e := runIn(t, "password1\npassword1\n", "webssh", "create-admin", "--username", "admin1"); code != 0 {
		t.Fatalf("create-admin: %s", e)
	}
	ctx := t.Context()
	cfg, _ := loadConfig()
	g, err := openGoData(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	server := g.sessions
	var got []principal.Revocation
	server.Subscribe(func(r principal.Revocation) { got = append(got, r) })
	if _, err := server.FollowRevocations(ctx); err != nil {
		t.Fatal(err)
	}
	code, out, e := runIn(t, "password2\npassword2\n", "webssh", "reset-password", "--username", "admin1")
	if code != 0 {
		t.Fatalf("reset: %d %s", code, e)
	}
	if _, err := server.FollowRevocations(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = g.db.Read(ctx, func(tx *store.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM session_revocations`).Scan(&n)
	})
	_ = g.Close()
	if !strings.Contains(out, "SSH sessions and persistent tmux sessions end") {
		t.Fatalf("output: %q", out)
	}
	if len(got) != 1 || got[0].SessionID != "" || got[0].UserID <= 0 || got[0].Reason != principal.ReasonPasswordChanged {
		t.Fatalf("server received %+v, want one account-wide password_changed revocation (journal rows: %d)", got, n)
	}
}
