package legacy

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// N10: a store above Python's size limit is one Python refuses to read:
// STOP.
func TestStoreSizeLimits(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	path := filepath.Join(dir, "users", "user_3", "host_context.json")
	big := `{"version": 1, "hosts": {}, "pad": "` + strings.Repeat("x", hostContextStoreBytes) + `"}`
	if err := os.WriteFile(path, []byte(big), 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := Open(t.Context(), dir, golden.manifest.SecretKey.Value)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	if _, err := src.UserDocuments(3); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v", err)
	}
	if err := os.WriteFile(path, []byte(big[:hostContextStoreBytes-100]+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := src.UserDocuments(3); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	cred := filepath.Join(dir, "users", "user_3", "credentials.json")
	data, _ := os.ReadFile(cred)
	if err := os.WriteFile(cred, append(data, make([]byte, automationStoreBytes)...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := src.NamedCredentials(t.Context(), 3); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("credentials: %v", err)
	}
}

// N10: numbers survive as written, also above 2^53.
func TestStoreNumbersAreLossless(t *testing.T) {
	t.Parallel()
	doc, err := decodeStore([]byte(`{"schema_version": 2, "big": 9007199254740993, "neg": -12345678901234567890, "f": 1.50e3, "z": -0.0}`), userStores[5])
	if err != nil {
		t.Fatal(err)
	}
	if doc.Object["big"] != Number("9007199254740993") || doc.Object["neg"] != Number("-12345678901234567890") {
		t.Fatalf("numbers: %#v", doc.Object)
	}
	if n, ok := doc.Object["big"].(Number).Int64(); !ok || n != 9007199254740993 {
		t.Errorf("Int64 %d %v", n, ok)
	}
	if _, ok := doc.Object["neg"].(Number).Int64(); ok {
		t.Error("Int64 accepted a value outside int64")
	}
	if f, err := doc.Object["f"].(Number).Float64(); err != nil || f != 1500 {
		t.Errorf("Float64 %v %v", f, err)
	}
	for v, want := range map[Number]bool{"0": false, "-0": false, "0.0": false, "0e7": false, "1e-400": false, "1": true, "-12345678901234567890": true, "1e400": true} {
		if truthy(v) != want {
			t.Errorf("truthy(%s) = %v", v, !want)
		}
	}
}

// K3 R1: one lone surrogate in a key name does not stop the migration;
// the store is flagged.
func TestKeyNameWithLoneSurrogate(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	path := filepath.Join(dir, "users", "user_3", "keys", "keys.json")
	data, _ := os.ReadFile(path)
	first := strings.Index(string(data), `"name": "`)
	if first < 0 {
		t.Fatalf("no name in keys.json: %s", data)
	}
	changed := string(data[:first]) + `"name": "\ud800 ` + string(data[first+len(`"name": "`):])
	if err := os.WriteFile(path, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := Open(t.Context(), dir, golden.manifest.SecretKey.Value)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	keys, err := src.SSHKeys(3)
	if err != nil {
		t.Fatal(err)
	}
	if !keys.LoneSurrogates || !slices.ContainsFunc(keys.Keys, func(k SSHKey) bool { return strings.HasPrefix(k.Name, "� ") }) {
		t.Errorf("flag %v, names %v", keys.LoneSurrogates, keys.Keys)
	}
}
