package e2eseed

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const checkedInSeed = "../../tests/e2e/seed.json"

func readSeed(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(checkedInSeed)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// mutate decodes the checked-in seed into a generic tree, applies edit and
// re-encodes it, so each negative case differs in exactly one place.
func mutate(t *testing.T, edit func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(readSeed(t), &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func list(m map[string]any, key string) []any { return m[key].([]any) }
func entry(m map[string]any, key string, i int) map[string]any {
	return list(m, key)[i].(map[string]any)
}

func TestCheckedInSeedDecodes(t *testing.T) {
	t.Parallel()
	s, err := Load(checkedInSeed)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Accounts) != 7 || len(s.Profiles) != 24 || len(s.TestHooks) != 5 {
		t.Fatalf("accounts=%d profiles=%d hooks=%d", len(s.Accounts), len(s.Profiles), len(s.TestHooks))
	}
	if g := s.Guard(); g == nil || g.message != "E2E network guard reached" {
		t.Fatalf("guard = %+v", g)
	}
	var empty *string
	for _, p := range s.Profiles {
		if p.ID == "post-command-empty" {
			empty = p.ParametersOverride
		}
	}
	if empty == nil || *empty != "" {
		t.Fatal("an empty parameters_override must stay distinguishable from a missing one")
	}
}

func TestDecodeFailsClosed(t *testing.T) {
	t.Parallel()
	cases := map[string]func(m map[string]any){
		"version 2":              func(m map[string]any) { m["version"] = 2 },
		"version missing":        func(m map[string]any) { delete(m, "version") },
		"version as string":      func(m map[string]any) { m["version"] = "1" },
		"unknown member":         func(m map[string]any) { m["extra"] = true },
		"unknown nested member":  func(m map[string]any) { entry(m, "profiles", 0)["color"] = "red" },
		"member in another case": func(m map[string]any) { entry(m, "accounts", 0)["Admin"] = true },
		"unknown hook": func(m map[string]any) {
			m["test_hooks"] = append(list(m, "test_hooks"), map[string]any{"name": "socket_anything"})
		},
		"hook twice": func(m map[string]any) {
			m["test_hooks"] = append(list(m, "test_hooks"), map[string]any{"name": "socket_output_load"})
		},
		"hook with members":        func(m map[string]any) { entry(m, "test_hooks", 2)["error"] = "x" },
		"guard without text":       func(m map[string]any) { delete(entry(m, "test_hooks", 1), "error") },
		"guard text with control":  func(m map[string]any) { entry(m, "test_hooks", 1)["error"] = "bad\x1b[2J" },
		"guard text too long":      func(m map[string]any) { entry(m, "test_hooks", 1)["error"] = strings.Repeat("x", 201) },
		"peer without accounts":    func(m map[string]any) { delete(entry(m, "test_hooks", 0), "accounts") },
		"peer with unknown acount": func(m map[string]any) { entry(m, "test_hooks", 0)["accounts"] = []any{"nobody"} },
		"duplicate account ref":    func(m map[string]any) { entry(m, "accounts", 1)["ref"] = "admin" },
		"duplicate username":       func(m map[string]any) { entry(m, "accounts", 1)["username"] = "e2e_admin" },
		"empty password":           func(m map[string]any) { entry(m, "accounts", 1)["password"] = "" },
		"data file with path":      func(m map[string]any) { m["data_files"] = map[string]any{"../escape": "x"} },
		"data file dot dot":        func(m map[string]any) { m["data_files"] = map[string]any{"..": "x"} },
		"data file absolute":       func(m map[string]any) { m["data_files"] = map[string]any{"/etc/x": "x"} },
		"seed moves DATA_DIR":      func(m map[string]any) { m["environment"].(map[string]any)["DATA_DIR"] = "/tmp" },
		"seed sets test switch": func(m map[string]any) {
			m["environment"].(map[string]any)["WEBSSH_E2E_FAST_HASHING"] = "1"
		},
		"lower-case variable":     func(m map[string]any) { m["environment"].(map[string]any)["path"] = "x" },
		"data_dir file with path": func(m map[string]any) { m["environment"].(map[string]any)["X_FILE"] = "{data_dir}/../x" },
		"unset and set":           func(m map[string]any) { m["unset_environment"] = []any{"DEBUG"} },
		"unknown key ref":         func(m map[string]any) { entry(m, "profiles", 5)["key"] = "nope" },
		"unknown jump ref":        func(m map[string]any) { entry(m, "profiles", 6)["jump_host"] = "nope" },
		"unknown socks ref":       func(m map[string]any) { entry(m, "profiles", 9)["socks_proxy"] = "nope" },
		"ref and literal id":      func(m map[string]any) { entry(m, "profiles", 5)["key_id"] = "x" },
		"ref of another account":  func(m map[string]any) { entry(m, "profiles", 5)["account"] = "user" },
		"jump key unknown":        func(m map[string]any) { entry(m, "jump_hosts", 0)["key"] = "nope" },
		"duplicate key ref": func(m map[string]any) {
			m["ssh_keys"] = append(list(m, "ssh_keys"), entry(m, "ssh_keys", 0))
		},
		"rsa key":                func(m map[string]any) { entry(m, "ssh_keys", 0)["generate"] = "rsa" },
		"profile id twice":       func(m map[string]any) { entry(m, "profiles", 1)["id"] = "password-review" },
		"profile port 0":         func(m map[string]any) { entry(m, "profiles", 1)["port"] = 0 },
		"unknown profile owner":  func(m map[string]any) { entry(m, "profiles", 1)["account"] = "ghost" },
		"unknown command owner":  func(m map[string]any) { entry(m, "commands", 0)["account"] = "ghost" },
		"command without owner":  func(m map[string]any) { delete(entry(m, "command_sets", 0), "account") },
		"unknown identity owner": func(m map[string]any) { entry(m, "external_identities", 0)["account"] = "ghost" },
		"unknown feature author": func(m map[string]any) { entry(m, "security_features", 0)["updated_by"] = "ghost" },
		"unknown mfa type":       func(m map[string]any) { entry(m, "mfa_placeholders", 0)["type"] = "sms" },
		"totp with passkey data": func(m map[string]any) { entry(m, "mfa_placeholders", 0)["credential_id"] = "x" },
		"passkey with secret":    func(m map[string]any) { entry(m, "mfa_placeholders", 1)["secret"] = "x" },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := Decode(mutate(t, edit))
			t.Log(err)
			if err == nil {
				t.Fatal("seed accepted")
			}
		})
	}
}

func TestDecodeRejectsDuplicateAndTrailing(t *testing.T) {
	t.Parallel()
	data := string(readSeed(t))
	for name, bad := range map[string]string{
		"duplicate top-level":  strings.Replace(data, `"version": 1,`, `"version": 1, "version": 1,`, 1),
		"duplicate in skipped": strings.Replace(data, `"id": "e2e-command",`, `"id": "e2e-command", "id": "x",`, 1),
		"trailing data":        data + "{}",
		"not an object":        "[]",
	} {
		if _, err := Decode([]byte(bad)); err == nil {
			t.Errorf("%s: seed accepted", name)
		}
	}
}

func TestLoadBoundsTheFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "seed.json")
	big := `{"version": 1, "environment": {"X": "` + strings.Repeat("a", maxSeedSize) + `"}}`
	if err := os.WriteFile(path, []byte(big), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("Load = %v", err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("missing seed accepted")
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(readSeedForFuzz(f))
	f.Add([]byte(`{"version":1}`))
	f.Add([]byte(`{"version":1,"test_hooks":[{"name":"outbound_ssh_guard","error":"x"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := Decode(data)
		if err != nil {
			return
		}
		// An accepted seed validates again and keeps its invariants.
		if err := s.Validate(); err != nil {
			t.Fatalf("decoded seed fails Validate: %v", err)
		}
		for name := range s.DataFiles {
			if !plainFileName(name) {
				t.Fatalf("data file %q accepted", name)
			}
		}
		if g := s.Guard(); g != nil && !safeMessage(g.message) {
			t.Fatalf("guard text %q accepted", g.message)
		}
		if !jsontext.Value(data).IsValid() {
			t.Fatal("invalid JSON accepted")
		}
	})
}

func readSeedForFuzz(f *testing.F) []byte {
	data, err := os.ReadFile(checkedInSeed)
	if err != nil {
		f.Fatal(err)
	}
	return data
}
