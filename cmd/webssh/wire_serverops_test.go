package main

import (
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/store"
)

func setHerdrSwitch(t *testing.T, sys *system, on bool) {
	t.Helper()
	v := "false"
	if on {
		v = "true"
	}
	err := sys.db.Write(t.Context(), func(tx *store.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO settings_app (key, value, source, rule, updated_us) VALUES ('herdr_enabled', ?, 'admin', '', 1)
ON CONFLICT (key) DO UPDATE SET value = excluded.value`, v)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The snapshot asks the same Herdr decision as the terminal, and it reads
// the switch and the saved host at every call: a change after connect
// takes the overview away at the next request.
func TestHerdrOverviewIsDecidedAtEachRequest(t *testing.T) {
	sys, _ := openTestSystem(t, nil)
	ctx := context.Background()
	v := func(s string) jsontext.Value { return jsontext.Value(s) }
	save := protocol.HostsProfileSave{Name: v(`"h"`), Host: v(`"h.example"`), Username: v(`"u"`),
		AuthType: v(`"password"`), Herdr: v(`true`)}
	out, err := sys.hosts.SaveProfile(ctx, 1, save)
	if err != nil {
		t.Fatal(err)
	}
	var saved struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(out, &saved); err != nil || saved.ID == "" {
		t.Fatalf("saved %s: %v", out, err)
	}
	g := herdrGrants{sys}
	if g.Overview(ctx, 1, saved.ID) {
		t.Fatal("overview with the integration off")
	}
	setHerdrSwitch(t, sys, true)
	if !g.Overview(ctx, 1, saved.ID) {
		t.Fatal("no overview with the switch on and the host option set")
	}
	if g.Overview(ctx, 2, saved.ID) || g.Overview(ctx, 1, "missing") || g.Overview(ctx, 1, "") {
		t.Fatal("overview for another account's or a missing host")
	}
	save.ID, save.Herdr = v(`"`+saved.ID+`"`), v(`false`)
	if _, err := sys.hosts.SaveProfile(ctx, 1, save); err != nil {
		t.Fatal(err)
	}
	if g.Overview(ctx, 1, saved.ID) {
		t.Fatal("overview kept after the host dropped the option")
	}
	if _, ok := (liveSessions{sys.terminal}).Live(1, "no-such-session"); ok {
		t.Fatal("a missing session is live")
	}
	if !strings.Contains(string(out), `"herdr":true`) {
		t.Fatalf("saved host does not show the option: %s", out)
	}
}
