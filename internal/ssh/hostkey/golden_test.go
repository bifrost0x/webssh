package hostkey

import (
	"archive/tar"
	"encoding/base64"
	json "encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// goldenRoot is the golden data set of the repository (tests/golden). It
// is part of the repository, so a missing file fails the test.
func goldenRoot(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "tests", "golden", "fixture")
	if _, err := os.Stat(filepath.Join(dir, "datadir.tar")); err != nil {
		t.Fatalf("golden data set missing: %v", err)
	}
	return dir
}

func readTarFiles(t *testing.T, path string, names ...string) map[string][]byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	out := map[string][]byte{}
	r := tar.NewReader(f)
	for {
		h, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if slices.Contains(names, h.Name) {
			data, err := io.ReadAll(io.LimitReader(r, 1<<20))
			if err != nil {
				t.Fatal(err)
			}
			out[h.Name] = data
		}
	}
	for _, n := range names {
		if _, ok := out[n]; !ok {
			t.Fatalf("%s missing in %s", n, path)
		}
	}
	return out
}

func TestGoldenHostKeys(t *testing.T) {
	dir := goldenRoot(t)
	files := readTarFiles(t, filepath.Join(dir, "datadir.tar"), "data/known_hosts", "data/users/user_3/known_hosts")
	global, err := Parse(files["data/known_hosts"])
	if err != nil {
		t.Fatalf("global: %v", err)
	}
	user, err := Parse(files["data/users/user_3/known_hosts"])
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	trust := Trust{User: user, Global: global}

	var manifest struct {
		Values struct {
			HostKeys struct {
				UserEntries []struct {
					Host        string `json:"host"`
					KeyType     string `json:"key_type"`
					Fingerprint string `json:"fingerprint_sha256"`
				} `json:"user_entries"`
				GlobalLines []string `json:"global_lines"`
			} `json:"host_keys"`
			EdgeCases struct {
				HostKeyDeleted struct {
					Host string `json:"deleted_host"`
				} `json:"host_key_deleted"`
			} `json:"edge_cases"`
		} `json:"values"`
	}
	readJSON(t, filepath.Join(dir, "manifest.json"), &manifest)

	deleted := manifest.Values.EdgeCases.HostKeyDeleted.Host
	for _, e := range manifest.Values.HostKeys.UserEntries {
		known := trust.Lookup(e.Host)
		if e.Host == deleted {
			if len(known) != 0 {
				t.Errorf("%s was deleted but is still trusted", e.Host)
			}
			continue
		}
		if len(known) != 1 || known[0].Type != e.KeyType || Fingerprint(known[0].Key) != e.Fingerprint || known[0].Scope != ScopeUser {
			t.Errorf("%s: want %s %s, got %+v", e.Host, e.KeyType, e.Fingerprint, known)
		}
		if v := trust.Verify(e.Host, known[0].Key); v != Trusted {
			t.Errorf("%s: verdict %s", e.Host, v)
		}
	}
	if len(global.Trusted) != 1 || len(global.Revoked) != 1 {
		t.Fatalf("global: %d trusted, %d revoked", len(global.Trusted), len(global.Revoked))
	}
	if v := trust.Verify("compromised.golden.test", global.Revoked[0].Key); v != Revoked {
		t.Errorf("revoked key verdict %s", v)
	}
	if v := trust.Verify("bastion.golden.test", global.Trusted[0].Key); v != Trusted {
		t.Errorf("global key verdict %s", v)
	}

	var python struct {
		Global  []oracleListEntry      `json:"global"`
		User    []oracleListEntry      `json:"user"`
		Lookups map[string][][2]string `json:"lookups"`
	}
	readJSON(t, filepath.Join("testdata", "golden.json"), &python)
	for scope, want := range map[Scope][]oracleListEntry{ScopeGlobal: python.Global, ScopeUser: python.User} {
		raw, owner := files["data/known_hosts"], ""
		if scope == ScopeUser {
			raw, owner = files["data/users/user_3/known_hosts"], "3"
		}
		got, err := List(raw, scope, owner)
		if err != nil || len(got) != len(want) {
			t.Fatalf("%s list: %v, %d vs %d", scope, err, len(got), len(want))
		}
		for i := range want {
			if got[i].ID != want[i].ID || got[i].Fingerprint != want[i].Fingerprint || got[i].Hosts[0].Host != want[i].Host {
				t.Errorf("%s[%d]: python %+v, go %+v", scope, i, want[i], got[i])
			}
		}
	}
	for host, want := range python.Lookups {
		var got [][2]string
		for _, k := range trust.Lookup(host) {
			got = append(got, [2]string{k.Type, base64.StdEncoding.EncodeToString(k.Key.Marshal())})
		}
		if !slices.Equal(got, want) {
			t.Errorf("lookup %s: python %v, go %v", host, want, got)
		}
	}
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}
