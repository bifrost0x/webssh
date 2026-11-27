package ldap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeFile(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func testCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, IsCA: true,
		BasicConstraintsValid: true, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestReadSecret(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if got, err := readSecret(writeFile(t, dir, "ok", "s3cret\r\n\n", 0o600)); err != nil || got != "s3cret" {
		t.Fatalf("ok: %q %v", got, err)
	}
	bad := map[string]string{
		"empty": writeFile(t, dir, "empty", "\n", 0o600),
		"nul":   writeFile(t, dir, "nul", "a\x00b", 0o600),
		"utf8":  writeFile(t, dir, "utf8", "a\xffb", 0o600),
		"large": writeFile(t, dir, "large", strings.Repeat("a", maxSecretBytes+1), 0o600),
		"dir":   dir,
		"none":  filepath.Join(dir, "missing"),
	}
	bad["group readable"] = writeFile(t, dir, "wide", "x", 0o640)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(filepath.Join(dir, "ok"), link); err != nil {
		t.Fatal(err)
	}
	bad["symlink"] = link
	for name, path := range bad {
		if _, err := readSecret(path); !errors.Is(err, ErrUnavailable) {
			t.Errorf("%s: want ErrUnavailable, got %v", name, err)
		}
	}
}

func TestLoadCA(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	ca := testCA(t)
	if _, err := loadCA(writeFile(t, dir, "ok", "comment\n"+ca+"\nmore", 0o644)); err != nil {
		t.Fatalf("ok: %v", err)
	}
	for name, content := range map[string]string{
		"empty":     "",
		"no cert":   "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
		"not ascii": ca + "é",
		"broken":    "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
		"too large": ca + strings.Repeat("x", maxCABytes),
	} {
		if _, err := loadCA(writeFile(t, dir, strings.ReplaceAll(name, " ", "_"), content, 0o644)); !errors.Is(err, ErrUnavailable) {
			t.Errorf("%s: want ErrUnavailable, got %v", name, err)
		}
	}
}

func testSettings(t *testing.T) Settings {
	t.Helper()
	dir := t.TempDir()
	return Settings{Provider: "corp", URL: "ldap://dir.example.test", BaseDN: "dc=example", BindDN: "cn=svc,dc=example",
		BindPasswordFile: writeFile(t, dir, "pw", "secret\n", 0o600), CAFile: writeFile(t, dir, "ca.pem", testCA(t), 0o644),
		UserFilter: "(uid={username})", UniqueIDAttribute: "entryUUID", ConnectTimeout: time.Second, OperationTimeout: time.Second}
}

// TestFilterThatDoesNotCompileDoesNotBlockStart is condition K7/A2: the
// client is built, only Ready reports the filter, and a lookup answers
// "unavailable" like the Python release (Bonsai's FilterError).
func TestFilterThatDoesNotCompileDoesNotBlockStart(t *testing.T) {
	t.Parallel()
	s := testSettings(t)
	s.UserFilter = "(&(uid={username})"
	c, err := NewClient(s)
	if err != nil {
		t.Fatalf("a broken filter must not stop the start: %v", err)
	}
	if err := c.Ready(); !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "LDAP_USER_FILTER") {
		t.Fatalf("ready: %v", err)
	}
	if _, err := c.Lookup(t.Context(), "alice"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("lookup: %v", err)
	}
}

func TestClientReady(t *testing.T) {
	t.Parallel()
	s := testSettings(t)
	c, err := NewClient(s)
	if err != nil || c.Ready() != nil || c.Transport() != "ldap+StartTLS" {
		t.Fatalf("ready: %v %v", err, c.Ready())
	}
	s.URL = "ldaps://dir.example.test"
	if c, _ := NewClient(s); c.Transport() != "ldaps" {
		t.Fatal("transport")
	}
	s.BindPasswordFile = filepath.Join(t.TempDir(), "missing")
	if c, _ := NewClient(s); c.Ready() == nil {
		t.Fatal("missing password file must not be ready")
	}
	for _, bad := range []string{"http://x", "ldap://x/dc=a"} {
		s.URL = bad
		if _, err := NewClient(s); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestLookupRefusesNamesWithoutNetwork(t *testing.T) {
	t.Parallel()
	s := testSettings(t)
	s.Dial = nil
	c, err := NewClient(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", " \t ", strings.Repeat("a", 257), "a\xff"} {
		if _, err := c.Lookup(t.Context(), name); !errors.Is(err, ErrRejected) {
			t.Errorf("%q: want ErrRejected, got %v", name, err)
		}
	}
	if ok, err := c.VerifyPassword(t.Context(), "uid=a", ""); ok || err != nil {
		t.Fatalf("empty password: %v %v", ok, err)
	}
}
