package client

import (
	"archive/tar"
	"encoding/base64"
	json "encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// goldenDir is the golden data set of the repository (tests/golden).
var goldenDir = filepath.Join("..", "..", "..", "tests", "golden", "fixture")

type goldenKey struct {
	Label        string `json:"label"`
	Algorithm    string `json:"algorithm"`
	Format       string `json:"format"`
	Protected    bool   `json:"passphrase_protected"`
	Public       string `json:"public_key_openssh"`
	PlaintextB64 string `json:"plaintext_b64"`
	KeyType      string `json:"key_type"`
	Error        string `json:"expected_error"`
}

func goldenKeys(t *testing.T) (stored, rejected []goldenKey) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(goldenDir, "manifest.json"))
	if err != nil {
		t.Fatalf("golden data set missing: %v", err)
	}
	var m struct {
		Values struct {
			SSHKeys struct {
				Stored   []goldenKey `json:"stored"`
				Rejected []goldenKey `json:"rejected"`
			} `json:"ssh_keys"`
		} `json:"values"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m.Values.SSHKeys.Stored, m.Values.SSHKeys.Rejected
}

// Every key the Python app stored must load and yield the same public key.
func TestGoldenStoredKeysLoad(t *testing.T) {
	stored, _ := goldenKeys(t)
	if len(stored) == 0 {
		t.Fatal("no stored keys in manifest")
	}
	for _, k := range stored {
		pemBytes, err := base64.StdEncoding.DecodeString(k.PlaintextB64)
		if err != nil {
			t.Fatal(err)
		}
		signer, kind, err := ParsePrivateKey(pemBytes, nil)
		if err != nil {
			t.Errorf("%s: %v", k.Label, err)
			continue
		}
		if string(kind) != k.KeyType {
			t.Errorf("%s: type %s, python %s", k.Label, kind, k.KeyType)
		}
		want, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k.Public))
		if err != nil {
			t.Fatal(err)
		}
		if string(signer.PublicKey().Marshal()) != string(want.Marshal()) {
			t.Errorf("%s: public key differs", k.Label)
		}
	}
}

// Keys Python rejected at upload: Go reads the same formats except that
// unencrypted PKCS#8 now loads. Passphrase-protected keys report that a
// passphrase is needed, and load with it.
func TestGoldenRejectedKeys(t *testing.T) {
	_, rejected := goldenKeys(t)
	for _, k := range rejected {
		pemBytes, _ := base64.StdEncoding.DecodeString(k.PlaintextB64)
		_, _, err := ParsePrivateKey(pemBytes, nil)
		switch {
		case k.Format == "pkcs8" && !k.Protected:
			if err != nil {
				t.Errorf("%s: plain PKCS#8 should load: %v", k.Label, err)
			}
		case k.Format == "pkcs8":
			if !errors.Is(err, ErrUnsupportedKey) {
				t.Errorf("%s: encrypted PKCS#8: %v", k.Label, err)
			}
		default:
			if !errors.Is(err, ErrPassphraseRequired) {
				t.Errorf("%s: %v", k.Label, err)
				continue
			}
			if _, _, err := ParsePrivateKey(pemBytes, []byte("golden key passphrase")); err != nil {
				t.Errorf("%s with passphrase: %v", k.Label, err)
			}
		}
		if strings.Contains(k.Error, "Passphrase") != k.Protected && k.Format != "pkcs8" {
			t.Errorf("%s: manifest error %q", k.Label, k.Error)
		}
	}
}

func TestParsePrivateKeyRejects(t *testing.T) {
	for name, in := range map[string]string{
		"empty":   "",
		"garbage": "not a key",
		"dsa pem": "-----BEGIN DSA PRIVATE KEY-----\nAAAA\n-----END DSA PRIVATE KEY-----\n",
	} {
		if _, _, err := ParsePrivateKey([]byte(in), nil); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, _, err := ParsePrivateKey([]byte("-----BEGIN DSA PRIVATE KEY-----\nAAAA\n-----END DSA PRIVATE KEY-----\n"), nil); !errors.Is(err, ErrDSAKey) {
		t.Errorf("dsa: %v", err)
	}
	big := make([]byte, maxKeyBytes+1)
	if _, _, err := ParsePrivateKey(big, nil); !errors.Is(err, ErrUnsupportedKey) {
		t.Errorf("oversized: %v", err)
	}
}

// A key file from before at-rest encryption is plain PEM on disk.
func TestGoldenLegacyPlaintextKeyFile(t *testing.T) {
	dir := goldenDir
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatalf("golden data set missing: %v", err)
	}
	var m struct {
		Values struct {
			SSHKeys struct {
				Legacy struct {
					File    string `json:"stored_file"`
					KeyType string `json:"key_type"`
				} `json:"legacy_plaintext"`
			} `json:"ssh_keys"`
		} `json:"values"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	pemBytes := tarFile(t, filepath.Join(dir, "datadir.tar"), "data/"+m.Values.SSHKeys.Legacy.File)
	_, kind, err := ParsePrivateKey(pemBytes, nil)
	if err != nil || string(kind) != m.Values.SSHKeys.Legacy.KeyType {
		t.Fatalf("legacy plaintext key: %s %v", kind, err)
	}
}

func tarFile(t *testing.T, path, name string) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	r := tar.NewReader(f)
	for {
		h, err := r.Next()
		if err != nil {
			t.Fatalf("%s not found: %v", name, err)
		}
		if h.Name == name {
			data, err := io.ReadAll(io.LimitReader(r, 1<<20))
			if err != nil {
				t.Fatal(err)
			}
			return data
		}
	}
}
