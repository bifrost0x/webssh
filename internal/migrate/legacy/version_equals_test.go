package legacy

import (
	"testing"

	"github.com/bifrost0x/webssh/internal/automation"
	"github.com/bifrost0x/webssh/internal/pyjson"
)

// automation.json, automation-runs.json and credentials.json are valid in
// Python when "version" == 1, which also holds for 1.0, 1e0 and true
// (app/automation_store.py _valid_books, automation_service.py
// _read_history, credential_store.py _valid). A hand-edited file with such
// a version must migrate instead of stopping the first start; 2, "1" and
// null still stop it. automation-vault.json checks type(...) is int and
// stays strict.
func TestVersionsPythonComparesEqualToOne(t *testing.T) {
	t.Parallel()
	spec := func(name string) storeSpec {
		for _, s := range userStores {
			if s.name == name {
				return s
			}
		}
		t.Fatalf("no store %s", name)
		return storeSpec{}
	}
	docs := map[string]string{
		"automation":      `{"version": %s, "runbooks": []}`,
		"automation_runs": `{"version": %s, "runs": []}`,
		"credentials":     `{"version": %s, "credentials": {}, "assignments": {}, "imports": []}`,
	}
	fill := func(format, version string) []byte {
		out := []byte{}
		for i := 0; i < len(format); i++ {
			if format[i] == '%' && i+1 < len(format) && format[i+1] == 's' {
				out = append(out, version...)
				i++
				continue
			}
			out = append(out, format[i])
		}
		return out
	}
	parse := map[string]func([]byte) error{
		"automation": func(b []byte) error { _, err := parseRunbooks(b); return err },
		"automation_runs": func(b []byte) error {
			doc, _, err := pyjson.Load(b)
			if err != nil {
				return err
			}
			_, err = automation.ParseHistory(doc)
			return err
		},
		"credentials": func(b []byte) error { _, _, err := parseCredentialDocument(b); return err },
	}
	for name, format := range docs {
		for _, version := range []string{"1", "1.0", "1e0", "true"} {
			raw := fill(format, version)
			if _, err := decodeStore(raw, spec(name)); err != nil {
				t.Errorf("%s version %s: decodeStore: %v", name, version, err)
			}
			if err := parse[name](raw); err != nil {
				t.Errorf("%s version %s: parse: %v", name, version, err)
			}
		}
		for _, version := range []string{"2", "0", "false", `"1"`, "null", "1.5"} {
			raw := fill(format, version)
			_, derr := decodeStore(raw, spec(name))
			if derr == nil && parse[name](raw) == nil {
				t.Errorf("%s version %s accepted", name, version)
			}
		}
	}
	for _, version := range []string{"1.0", "true"} {
		if _, err := decodeStore(fill(`{"version": %s, "kdf": {}, "salt": "", "nonce": "", "ciphertext": ""}`, version), spec("automation_vault")); err == nil {
			t.Errorf("automation vault version %s accepted", version)
		}
	}
}
