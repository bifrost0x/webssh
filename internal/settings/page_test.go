package settings

import (
	json "encoding/json/v2"
	"os"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/keyring"
)

func TestPageValues(t *testing.T) {
	s, _ := newService(t, Environment{Values: map[string]bool{"TMUX_ENABLED": true}})
	ring, err := keyring.Open([]byte("page-test-secret-0123456789abcdef"), make([]byte, keyring.MaterialSize))
	if err != nil {
		t.Fatal(err)
	}
	pp := PageProvider{Settings: s, Scope: ring}
	ctx := t.Context()
	acct := Account{ID: 4, Username: "jörg", HistoryGeneration: "2026-11-02T09:00:00"}
	p, err := pp.Page(ctx, acct)
	if err != nil {
		t.Fatal(err)
	}
	// The default block, as the overview workspace spec reads it.
	if p.OverviewPreferencesJSON != `{"dismissed": [], "panels": null}` || p.TerminalAppearanceJSON != `{}` {
		t.Errorf("default blocks %s %s", p.OverviewPreferencesJSON, p.TerminalAppearanceJSON)
	}
	if p.ConnectionHistoryScope != ring.BrowserScope(4, "jörg", "2026-11-02T09:00:00") || !p.TmuxEnabled || !p.SupportLinksEnabled {
		t.Errorf("page %+v", p)
	}
	if _, err := s.Update(ctx, 4, Changes{
		OverviewPanels:     rawJSON(`[{"id":"hosts","w":4,"h":30,"hidden":false}]`),
		TerminalAppearance: rawJSON(`{"font_family":"Fira Code","line_height":1.20}`),
	}); err != nil {
		t.Fatal(err)
	}
	p, err = pp.Page(ctx, acct)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.OverviewPreferencesJSON, `"id": "hosts", "w": 4`) ||
		p.OverviewPreferencesJSON != `{"dismissed": [], "panels": [{"h": 30, "hidden": false, "id": "hosts", "w": 4}]}` {
		t.Errorf("overview block %s", p.OverviewPreferencesJSON)
	}
	if p.TerminalAppearanceJSON != `{"font_family": "Fira Code", "line_height": 1.2}` || p.TerminalAppearance["line_height"] != 1.2 {
		t.Errorf("appearance %s %v", p.TerminalAppearanceJSON, p.TerminalAppearance)
	}
	// Without the generation the namespace would not survive id reuse.
	if _, err := pp.Page(ctx, Account{ID: 4, Username: "jörg"}); err == nil {
		t.Error("page without generation")
	}
}

// TestPageScopeMatchesPython checks the browser namespace of every
// account of the golden data set end to end through the page values.
func TestPageScopeMatchesPython(t *testing.T) {
	raw, err := os.ReadFile("../../tests/golden/fixture/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		SecretKey struct {
			Value string `json:"value"`
		} `json:"secret_key"`
		Values struct {
			Users map[string]struct {
				ID        int64  `json:"id"`
				CreatedAt string `json:"created_at_db"`
				Scope     string `json:"connection_history_scope"`
			} `json:"users"`
		} `json:"values"`
	}
	if err := json.Unmarshal(raw, &m, json.RejectUnknownMembers(false)); err != nil {
		t.Fatal(err)
	}
	ring, err := keyring.Open([]byte(m.SecretKey.Value), make([]byte, keyring.MaterialSize))
	if err != nil {
		t.Fatal(err)
	}
	s, _ := newService(t, Environment{})
	pp := PageProvider{Settings: s, Scope: ring}
	for name, u := range m.Values.Users {
		p, err := pp.Page(t.Context(), Account{ID: u.ID, Username: name, HistoryGeneration: u.CreatedAt})
		if err != nil {
			t.Fatal(err)
		}
		if p.ConnectionHistoryScope != u.Scope {
			t.Errorf("%s: %s, Python %s", name, p.ConnectionHistoryScope, u.Scope)
		}
	}
}
