package legacy

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	json "encoding/json/v2"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// Vectors of the migration specification, section 2 (Incarnation), and
// further forms CPython accepts or rejects (checked against Python 3.15).
func TestPythonISOFormat(t *testing.T) {
	t.Parallel()
	tests := []struct{ in, want string }{
		{"2026-11-02 09:00:00.000000", "2026-11-02T09:00:00"},
		{"2026-11-02 09:00:00.250000+00:00", "2026-11-02T09:00:00.250000+00:00"},
		{"2026-11-02", "2026-11-02T00:00:00"},
		{"2026-11-02 09:00", "2026-11-02T09:00:00"},
		{"2026-11-02T09:00:01.5", "2026-11-02T09:00:01.500000"},
		{"2026-11-02 09:00:01.250000", "2026-11-02T09:00:01.250000"},
		{"2026-11-02 09:00:01.000001", "2026-11-02T09:00:01.000001"},
		{"20261102", "2026-11-02T00:00:00"},
		{"2026-W44-1", "2026-10-26T00:00:00"},
		{"2026W441", "2026-10-26T00:00:00"},
		{"2026-11-02T09", "2026-11-02T09:00:00"},
		{"2026-11-02T0900", "2026-11-02T09:00:00"},
		{"2026-11-02T09:00:00Z", "2026-11-02T09:00:00+00:00"},
		{"2026-11-02T09:00:00.1234567", "2026-11-02T09:00:00.123456"},
		{"2026-11-02T09:00:00,5", "2026-11-02T09:00:00.500000"},
		{"2026-11-02T24:00:00", "2026-11-03T00:00:00"},
		{"2026-12-31T24:00", "2027-01-01T00:00:00"},
		{"2026-11-02x09:00", "2026-11-02T09:00:00"},
		{"2026-11-02\u00fc09:00", "2026-11-02T09:00:00"},
		{"2026-11-02T09:00+0130", "2026-11-02T09:00:00+01:30"},
		{"2026-11-02T09:00:00-05", "2026-11-02T09:00:00-05:00"},
		{"2026-11-02T09:00:00+01:30:15.5", "2026-11-02T09:00:00+01:30:15.500000"},
		{"2026-11-02T09:00:00.000000+00:00", "2026-11-02T09:00:00+00:00"},
		{"2026-11-02T09:00:00-00:00", "2026-11-02T09:00:00+00:00"},
		{"0099-01-01", "0099-01-01T00:00:00"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			got, err := incarnationOf(tt.in)
			if err != nil || got != tt.want {
				t.Fatalf("incarnationOf(%q) = %q, %v, want %q", tt.in, got, err, tt.want)
			}
		})
	}
	for _, bad := range []string{"", "2026-11-02 09:00:00.", "2026-11-02T9:00", "2026-1-02", "2026-11-02T09:00:00 ",
		"0000-01-01", "2026-02-30", "2026-11-02T24:00:01", "2026-11-02T25:00", "2026-W54", "2026-11-02T09:00+24:00",
		"2026-11-02T09:00Z+01", "2026-11-02T09:00+1", "2026-11-0209", "2026-11-02T09:00:00.12a"} {
		if got, err := incarnationOf(bad); err == nil {
			t.Errorf("incarnationOf(%q) = %q, want error", bad, got)
		}
	}
}

// Property: the output is a fixed point (fromisoformat of the output
// prints the same text) and parsing never panics.
func FuzzPythonISOFormat(f *testing.F) {
	for _, s := range []string{"2026-11-02 09:00:00.250000", "2026-W44-1T24:00Z", "20261102T0900-0130", "2026-11-02T09:00:00+01:30:15.5"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out, err := pythonFromISOFormatToISO(s)
		if err != nil {
			return
		}
		again, err := pythonFromISOFormatToISO(out)
		if err != nil || again != out {
			t.Fatalf("%q -> %q -> %q, %v", s, out, again, err)
		}
	})
}

func TestPythonJSON(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   []any
		want string
	}{
		{"named credential context", []any{"webssh-named-credentials-v1", int64(3), "2026-11-02T09:00:02.250000", "4e37"}, `["webssh-named-credentials-v1",3,"2026-11-02T09:00:02.250000","4e37"]`},
		{"escapes", []any{"a\"b\\c\n\x01\x7f"}, `["a\"b\\c\n\u0001\u007f"]`},
		{"non-ASCII and astral", []any{"\u00fc\u2713\U0001F680"}, `["\u00fc\u2713\ud83d\ude80"]`},
		{"negative", []any{int64(-1)}, `[-1]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := pythonCompactJSON(tt.in...)
			if err != nil || got != tt.want {
				t.Fatalf("got %s, %v, want %s", got, err, tt.want)
			}
		})
	}
	if _, err := pythonCompactJSON(1.5); err == nil {
		t.Fatal("float accepted")
	}
}

// Property: the output is ASCII and decodes back to the input.
func FuzzPythonJSONString(f *testing.F) {
	f.Add("ü✓🚀\"\\\n\x00")
	f.Fuzz(func(t *testing.T, s string) {
		if !utf8.ValidString(s) {
			return
		}
		enc := pythonJSONString(s)
		for i := range len(enc) {
			if enc[i] >= 0x80 {
				t.Fatalf("non-ASCII output %q", enc)
			}
		}
		var back string
		if err := json.Unmarshal([]byte(enc), &back); err != nil || back != s {
			t.Fatalf("round trip %q -> %s -> %q, %v", s, enc, back, err)
		}
	})
}

func TestIsFernetToken(t *testing.T) {
	t.Parallel()
	token := "gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA=="
	tests := []struct {
		name string
		data string
		want bool
	}{
		{"token", token, true},
		{"pem", "-----BEGIN OPENSSH PRIVATE KEY-----\n" + token, false},
		{"pem after whitespace", "\n -----BEGIN RSA PRIVATE KEY-----", false},
		{"short", token[:40], false},
		{"other version byte", base64.URLEncoding.EncodeToString(append([]byte{0x81}, make([]byte, 80)...)), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isFernetToken([]byte(tt.data)); got != tt.want {
				t.Fatalf("isFernetToken = %v", got)
			}
		})
	}
}

func TestSafeNames(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name string
		key  bool
		bak  bool
	}{
		{"a.pem", true, true}, {"users/user_3/profiles.json", false, true}, {"", false, false},
		{"..", false, false}, {"keys.json", false, true}, {"a/../b", false, false}, {"/abs", false, false},
		{"a\\b", false, false}, {"c:x", true, false}, {"a//b", false, true}, {"./a", false, true}, {"//a", false, false}, {"a/../b", false, false}, {".", false, false},
	} {
		if safeKeyFilename(c.name) != c.key || safeBackupPath(c.name) != c.bak {
			t.Errorf("%q: key %v backup %v", c.name, safeKeyFilename(c.name), safeBackupPath(c.name))
		}
	}
}

func TestDecodeStoreVersions(t *testing.T) {
	t.Parallel()
	spec := storeSpec{name: "profiles", versionKey: "schema_version", versions: upTo(3), listKey: "profiles"}
	tests := []struct {
		name string
		doc  string
		ok   bool
	}{
		{"current", `{"schema_version":3,"profiles":[]}`, true},
		{"missing means 0", `{"profiles":[{"id":"a"}]}`, true},
		{"future", `{"schema_version":4,"profiles":[]}`, false},
		{"float", `{"schema_version":3.0,"profiles":[]}`, false},
		{"bool", `{"schema_version":true,"profiles":[]}`, false},
		{"string", `{"schema_version":"3","profiles":[]}`, false},
		{"negative", `{"schema_version":-1,"profiles":[]}`, false},
		{"duplicate member, the last wins", `{"schema_version":3,"schema_version":1}`, true},
		{"duplicate member, the last is future", `{"schema_version":1,"schema_version":4}`, false},
		{"invalid UTF-8", "{\"schema_version\":3,\"x\":\"\xff\"}", false},
		{"array", `[]`, false},
		{"null", `null`, false},
		{"list is a string", `{"profiles":"x"}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := decodeStore([]byte(tt.doc), spec)
			if (err == nil) != tt.ok {
				t.Fatalf("err = %v, want ok %v", err, tt.ok)
			}
		})
	}
}

// Python writes stores with ensure_ascii, so an unpaired surrogate is
// stored as an escape and read back; Go reads the store and flags it.
func TestDecodeStoreLoneSurrogate(t *testing.T) {
	t.Parallel()
	spec := storeSpec{name: "commands", topList: true}
	doc, err := decodeStore([]byte(`[{"id":"a","command":"echo \\ud800"}]`), spec)
	if err != nil || doc.LoneSurrogates {
		t.Fatalf("escaped backslash: %+v, %v", doc, err)
	}
	doc, err = decodeStore([]byte(`[{"id":"a","command":"echo \ud800 \ud83d\ude80"}]`), spec)
	if err != nil || !doc.LoneSurrogates || doc.Items[0].(map[string]any)["command"] != "echo \ufffd \U0001F680" {
		t.Fatalf("lone surrogate: %+v, %v", doc, err)
	}
	if _, err := decodeStore([]byte("[\"\xff\"]"), spec); err == nil {
		t.Fatal("raw invalid UTF-8 accepted")
	}
}

func TestDecodeCommandsForms(t *testing.T) {
	t.Parallel()
	spec := storeSpec{name: "commands", topList: true}
	tests := []struct {
		name string
		doc  string
		ok   bool
	}{
		{"list", `[]`, true},
		{"object v2", `{"schema_version":2,"commands":[{"id":"a"}]}`, true},
		{"object v1", `{"schema_version":1,"commands":[]}`, true},
		{"object v3", `{"schema_version":3,"commands":[]}`, false},
		{"object without version", `{"commands":[]}`, false},
		{"object float version", `{"schema_version":2.0,"commands":[]}`, false},
		{"object without list", `{"schema_version":2,"commands":{}}`, false},
		{"string", `"x"`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := decodeStore([]byte(tt.doc), spec); (err == nil) != tt.ok {
				t.Fatalf("err = %v, want ok %v", err, tt.ok)
			}
		})
	}
}

func FuzzDecodeStore(f *testing.F) {
	f.Add([]byte(`{"schema_version":3,"profiles":[{"id":"a","port":22}]}`))
	f.Add([]byte(`{"version":1,"hosts":{}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, spec := range userStores {
			doc, err := decodeStore(data, spec)
			if err == nil && !spec.topList && doc.Object == nil {
				t.Fatalf("%s: accepted without object", spec.name)
			}
		}
	})
}

func FuzzParseBackupManifest(f *testing.F) {
	f.Add([]byte(`{"files":[{"path":"app.db","sha256":"` + strings.Repeat("0", 64) + `","size":1}],"format_version":1}`))
	f.Add([]byte(`{"created_at":"2026-11-02T09:09:56.250000Z","data_schema_version":2,"files":[],"format_version":2,"producer":"webssh"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := parseBackupManifest(data)
		if err != nil {
			if !errors.Is(err, ErrBackup) {
				t.Fatalf("unexpected error kind %v", err)
			}
			return
		}
		for i, file := range m.Files {
			if !safeBackupPath(file.Path) || (i > 0 && m.Files[i-1].Path >= file.Path) {
				t.Fatalf("accepted unsafe or unsorted path %q", file.Path)
			}
		}
	})
}

func FuzzParseKnownHosts(f *testing.F) {
	f.Add([]byte("bastion.golden.test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOL2WzJx0sV/B6VxWU9MnxKJFrrYYNJle330w6TBemSK\n"))
	f.Add([]byte("@cert-authority * ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOL2WzJx0sV/B6VxWU9MnxKJFrrYYNJle330w6TBemSK\n# c\n\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		keys, err := parseKnownHosts(data)
		if err != nil {
			return
		}
		for _, k := range keys {
			if k.Key == nil || (k.Marker != "" && k.Marker != "revoked" && k.Marker != "cert-authority") || !strings.HasPrefix(k.Fingerprint, "SHA256:") {
				t.Fatalf("accepted entry %+v", k)
			}
		}
	})
}

func TestKnownHostsRejectsUnknownMarkerAndGarbage(t *testing.T) {
	t.Parallel()
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOL2WzJx0sV/B6VxWU9MnxKJFrrYYNJle330w6TBemSK"
	for _, data := range []string{"|1|c2FsdA==|aGFzaA== " + key, "!,host " + key, "@other * " + key, "host ssh-ed25519 notbase64", "host " + key + "\ngarbage", "host " + key + "\r\xff"} {
		if _, err := parseKnownHosts([]byte(data)); err == nil {
			t.Errorf("accepted %q", data)
		}
	}
	hashed := "|1|" + base64.StdEncoding.EncodeToString(make([]byte, 20)) + "|" + base64.StdEncoding.EncodeToString(make([]byte, 20))
	keys, err := parseKnownHosts([]byte("# comment\n\nhost " + key + " a comment\r\n@cert-authority * " + key + "\n" + hashed + ",!bad.host " + key + "\n"))
	if err != nil || len(keys) != 3 || keys[1].Marker != "cert-authority" {
		t.Fatalf("keys %v, %v", keys, err)
	}
}

func writeZip(t *testing.T, add func(*zip.Writer)) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add(zw)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "a.zip")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestBackupMemberTypes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		header zip.FileHeader
	}{
		{"symbolic link", func() zip.FileHeader {
			h := zip.FileHeader{Name: "data/link"}
			h.SetMode(fs.ModeSymlink | 0o777)
			return h
		}()},
		{"encrypted", zip.FileHeader{Name: "data/x", Flags: 0x1}},
		{"absolute", zip.FileHeader{Name: "/etc/passwd"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeZip(t, func(zw *zip.Writer) {
				h := tt.header
				h.Modified = time.Unix(0, 0)
				w, err := zw.CreateHeader(&h)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = w.Write([]byte("x"))
				m, _ := zw.Create(backupManifestName)
				_, _ = m.Write([]byte(`{"files":[],"format_version":1}`))
			})
			if _, err := OpenBackup(path, DefaultBackupLimits); !errors.Is(err, ErrBackup) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestOpenRejectsMissingOrLinkedDatabase(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if _, err := Open(t.Context(), dir, "secret"); err == nil {
		t.Fatal("opened a directory without app.db")
	}
	if err := os.Symlink(filepath.Join(golden.dataDir, "app.db"), filepath.Join(dir, "app.db")); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), dir, "secret"); err == nil {
		t.Fatal("opened a symlinked app.db")
	}
	if _, err := Open(t.Context(), golden.dataDir, ""); err == nil {
		t.Fatal("opened with an empty secret")
	}
}

// A wrong SECRET_KEY must make every secret fail closed, never decrypt to
// something else.
func TestWrongSecretFailsClosed(t *testing.T) {
	t.Parallel()
	src, err := Open(t.Context(), golden.dataDir, golden.manifest.SecretKey.Value+"x")
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	owner := golden.manifest.Values.Users["local_user"].ID
	if _, err := src.SSHKeys(owner); err == nil {
		t.Error("SSH keys decrypted with a wrong secret")
	}
	if _, err := src.TOTPSecrets(t.Context()); err == nil {
		t.Error("TOTP secrets decrypted with a wrong secret")
	}
	if _, err := src.GitHubConfiguration(t.Context()); err == nil {
		t.Error("GitHub secret decrypted with a wrong secret")
	}
	if _, _, err := src.NamedCredentials(t.Context(), owner); err == nil {
		t.Error("named credentials decrypted with a wrong secret")
	}
}
