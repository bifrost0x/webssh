package legacy

import (
	"database/sql"
	"slices"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/settings"
)

func appDoc(t *testing.T, s string) []pyjson.Member {
	t.Helper()
	v, _, err := pyjson.Load([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	m, _ := pyjson.Members(v)
	return m
}

// migrate_runtime_features: only explicit environment values count; an
// absent key takes it and is recorded, a recorded key follows it, an
// administrator's own value stays.
func TestMigrateRuntimeFeatures(t *testing.T) {
	t.Parallel()
	env := settings.Environment{Values: map[string]bool{"TMUX_ENABLED": false, "SFTP_CHMOD_ENABLED": true, "TMUX_DEFAULT": true},
		Explicit: map[string]bool{"TMUX_ENABLED": true, "SFTP_CHMOD_ENABLED": true}}
	tests := []struct{ in, want string }{
		{`{}`, `{"sftp_chmod_enabled":true,"tmux_enabled":false,"runtime_feature_migration":["sftp_chmod_enabled","tmux_enabled"]}`},
		{`{"tmux_enabled":true,"sftp_chmod_enabled":true}`, `{"tmux_enabled":true,"sftp_chmod_enabled":true}`},
		{`{"tmux_enabled":true,"runtime_feature_migration":["tmux_enabled"]}`,
			`{"tmux_enabled":false,"runtime_feature_migration":["tmux_enabled","sftp_chmod_enabled"],"sftp_chmod_enabled":true}`},
		{`{"sftp_chmod_enabled":true,"tmux_enabled":false,"runtime_feature_migration":["tmux_enabled"]}`,
			`{"sftp_chmod_enabled":true,"tmux_enabled":false,"runtime_feature_migration":["tmux_enabled"]}`},
	}
	for _, tc := range tests {
		got := string(pyjson.Object(migrateRuntimeFeatures(appDoc(t, tc.in), env)))
		if got != tc.want {
			t.Errorf("%s:\n got %s\nwant %s", tc.in, got, tc.want)
		}
	}
}

// migrate_feature_policies: absent choices are added with a fresh
// revision; an explicit AUTOMATION_ENABLED marks and drives the stored
// value; a change of the effective value rotates the revision.
func TestMigrateFeaturePolicies(t *testing.T) {
	t.Parallel()
	explicitOff := settings.Environment{Values: map[string]bool{"AUTOMATION_ENABLED": false}, Explicit: map[string]bool{"AUTOMATION_ENABLED": true}}
	implicit := settings.Environment{Values: map[string]bool{"AUTOMATION_ENABLED": false}}
	t.Run("absent", func(t *testing.T) {
		m, gen := migrateFeaturePolicies(appDoc(t, `{}`), explicitOff, true)
		doc := pyjson.Object(m)
		for _, k := range []string{"credentials_enabled", "automation_enabled", "automation_enabled_from_environment", "automation_effective_observed"} {
			if _, ok := pyjson.Get(doc, k); !ok {
				t.Errorf("%s missing in %s", k, doc)
			}
		}
		if v, _ := pyjson.Get(doc, "credentials_enabled"); string(v) != "true" {
			t.Errorf("credentials_enabled %s", v)
		}
		if !slices.Equal(gen, []string{"credentials_enabled_revision", "automation_enabled_revision"}) {
			t.Errorf("generated %v", gen)
		}
	})
	t.Run("stored values stay", func(t *testing.T) {
		in := `{"credentials_enabled":false,"credentials_enabled_revision":"r1","automation_enabled":true,"automation_enabled_revision":"r2","automation_effective_observed":true}`
		m, gen := migrateFeaturePolicies(appDoc(t, in), implicit, true)
		if got := string(pyjson.Object(m)); got != in || len(gen) != 0 {
			t.Errorf("%s %v", got, gen)
		}
	})
	t.Run("environment disables", func(t *testing.T) {
		in := `{"credentials_enabled":false,"credentials_enabled_revision":"r1","automation_enabled":true,"automation_enabled_revision":"r2","automation_enabled_from_environment":true,"automation_effective_observed":true}`
		m, gen := migrateFeaturePolicies(appDoc(t, in), explicitOff, false)
		doc := pyjson.Object(m)
		if v, _ := pyjson.Get(doc, "automation_enabled"); string(v) != "false" {
			t.Errorf("automation_enabled %s", v)
		}
		if v, _ := pyjson.Get(doc, "automation_enabled_revision"); string(v) == `"r2"` || !slices.Equal(gen, []string{"automation_enabled_revision"}) {
			t.Errorf("revision not rotated: %s %v", v, gen)
		}
	})
	t.Run("observed missing", func(t *testing.T) {
		in := `{"credentials_enabled":false,"credentials_enabled_revision":"r1","automation_enabled":false,"automation_enabled_revision":"r2"}`
		m, gen := migrateFeaturePolicies(appDoc(t, in), implicit, false)
		if v, _ := pyjson.Get(pyjson.Object(m), "automation_enabled_revision"); string(v) != `"r2"` || len(gen) != 0 {
			t.Errorf("a first observation rotated the revision: %s %v", v, gen)
		}
	})
}

func TestApplyStartupAdminRules(t *testing.T) {
	t.Parallel()
	mk := func(id int64, name string, admin, locked bool, m accounts.Manager) importedAccount {
		return importedAccount{acc: accounts.Account{ID: id, Username: name, IsAdmin: admin, IsLocked: locked, Managed: m}}
	}
	list := []importedAccount{mk(1, "ldap", true, false, accounts.ManagedLDAP), mk(2, "old", false, false, ""),
		mk(3, "listed", false, false, ""), mk(4, "lockedlisted", false, true, ""), mk(5, "gh", false, false, accounts.ManagedGitHub)}
	promoted, missing := applyStartupAdminRules(list, []string{"listed", "lockedlisted", "gh", "ghost"})
	if !slices.Equal(promoted, []string{"old", "listed"}) || !slices.Equal(missing, []string{"ghost"}) {
		t.Fatalf("promoted %v, missing %v", promoted, missing)
	}
	if list[3].acc.IsAdmin || list[4].acc.IsAdmin {
		t.Fatal("a locked or GitHub-managed account was promoted")
	}
}

func TestQuarantinedID(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]int64{
		"user_12_7e4cf8aa59be45c2be46c153bdb481cb": 12, "user_12_7E4CF8AA59BE45C2BE46C153BDB481CB": 0,
		"user_12": 0, "user_x_7e4cf8aa59be45c2be46c153bdb481cb": 0, "user_0_7e4cf8aa59be45c2be46c153bdb481cb": 0, "notes": 0,
	} {
		if id, ok := quarantinedID(name); id != want && ok {
			t.Errorf("%s: %d %v", name, id, ok)
		} else if want > 0 && (!ok || id != want) {
			t.Errorf("%s: %d %v", name, id, ok)
		}
	}
}

func TestValidEpoch(t *testing.T) {
	t.Parallel()
	good := strings.Repeat("ab", 32)
	for in, want := range map[string]bool{
		good: true, good + "\n": true, " " + good + "\r\n": true, strings.ToUpper(good): false,
		good[:63]: false, good + "0": false, good + "\u00a0": false, "": false,
	} {
		if validEpoch([]byte(in)) != want {
			t.Errorf("%q: want %v", in, want)
		}
	}
}

func TestHostContextValidation(t *testing.T) {
	t.Parallel()
	ok := `{"revision":2,"notes":"n","directories":["/srv"],"command_sets":["cs"]}`
	for in, want := range map[string]bool{
		ok: true,
		`{"revision":1,"notes":"","directories":[],"command_sets":[]}`:              true,
		`{"revision":0,"notes":"","directories":[],"command_sets":[]}`:              false,
		`{"revision":1.0,"notes":"","directories":[],"command_sets":[]}`:            false,
		`{"revision":true,"notes":"","directories":[],"command_sets":[]}`:           false,
		`{"revision":1,"notes":1,"directories":[],"command_sets":[]}`:               false,
		`{"revision":1,"notes":"","directories":["rel"],"command_sets":[]}`:         false,
		`{"revision":1,"notes":"","directories":["/a","/a"],"command_sets":[]}`:     false,
		`{"revision":1,"notes":"","directories":[],"command_sets":[""]}`:            false,
		`{"revision":1,"notes":"","directories":[],"command_sets":[],"extra":1}`:    false,
		`{"revision":1,"notes":"","directories":[],"command_set":[]}`:               false,
		`{"revision":1,"notes":"","directories":["/a\u0007"],"command_sets":[]}`:    false,
	} {
		_, _, _, valid := hostContext(pyjson.Member{Name: "p", Value: []byte(in)})
		if valid != want {
			t.Errorf("%s: valid %v", in, valid)
		}
	}
}

func TestDBTime(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]int64{
		"2026-11-02 09:00:00.250000":       1793610000250000,
		"2026-11-02 10:00:00.250000+01:00": 1793610000250000,
		"2026-11-02 09:00:00":              1793610000000000,
	} {
		got, err := dbTime(sql.NullString{String: in, Valid: true})
		if err != nil || got.UnixMicro() != want {
			t.Errorf("%s: %d %v", in, got.UnixMicro(), err)
		}
	}
	if z, err := dbTime(sql.NullString{}); err != nil || !z.IsZero() {
		t.Error("NULL")
	}
	if _, err := dbTime(sql.NullString{String: "yesterday", Valid: true}); err == nil {
		t.Error("garbage accepted")
	}
}

// The M1 registry covers every entity of the specification, with or
// without the optional stores.
func TestRegisterM1CoversEverything(t *testing.T) {
	t.Parallel()
	for _, m := range []M1{{}, {Passkeys: testPasskeys{}, Persistent: &testPersistent{}}} {
		r := m1Registry(t, m)
		if u := r.Uncovered(); len(u) != 0 {
			t.Fatalf("uncovered %v", u)
		}
	}
}
