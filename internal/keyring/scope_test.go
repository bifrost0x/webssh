package keyring

import (
	json "encoding/json/v2"
	"os"
	"testing"
)

// The golden data set (tests/golden) is a DATA_DIR written by the
// unmodified Python release; its manifest holds the namespace Python
// computed for every account.
const goldenManifest = "../../tests/golden/fixture/manifest.json"

func TestBrowserScopeMatchesPython(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(goldenManifest)
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
	if len(m.Values.Users) < 10 {
		t.Fatalf("%d users in the manifest", len(m.Values.Users))
	}
	r, err := Open([]byte(m.SecretKey.Value), katMaterial)
	if err != nil {
		t.Fatal(err)
	}
	for name, u := range m.Values.Users {
		if got := r.BrowserScope(u.ID, name, u.CreatedAt); got != u.Scope {
			t.Errorf("%s: scope %s, Python %s", name, got, u.Scope)
		}
	}
	// An account without created_at uses its password hash. Computed with
	// app/browser_identity.py of the Python release for a stub user.
	const nullCreated = "ee81449f0410bcdd349df2fd961d9b4de4b9e130608a10e19edb25b47c310b28"
	if got := r.BrowserScope(42, "jörg_ünïcødé", "$2b$12$abcdefghijklmnopqrstuv"); got != nullCreated {
		t.Errorf("created_at NULL: scope %s, Python %s", got, nullCreated)
	}
	other, err := Open([]byte(m.SecretKey.Value), seq(0x40, 0x5f))
	if err != nil {
		t.Fatal(err)
	}
	if other.BrowserScope(1, "a", "b") != r.BrowserScope(1, "a", "b") {
		t.Error("the namespace depends on the keyring material")
	}
}
