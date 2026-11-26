//go:build lab

// The lab test uploads the ten client key formats of the shared test lab
// (tests/lab) through the vault and signs in with each stored key. Run it
// with
//
//	go test -tags lab -run Lab ./internal/vault
//
// It fails, not skips, when the lab is not reachable.
package vault

import (
	"bytes"
	"context"
	json "encoding/json/v2"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/principal/principaltest"
)

type labFile struct {
	RuntimeDir string `json:"runtime_dir"`
	Services   map[string]struct {
		Host         string            `json:"host"`
		Port         int               `json:"port"`
		Fingerprints map[string]string `json:"host_key_fingerprints"`
	} `json:"services"`
}

func loadLab(t *testing.T) labFile {
	t.Helper()
	path := os.Getenv("WEBSSH_LAB_JSON")
	if path == "" {
		path = filepath.Join("..", "..", "tests", "lab", "runtime", "lab.json")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("lab not available (set WEBSSH_LAB_JSON): %v", err)
	}
	var l labFile
	if err := json.Unmarshal(raw, &l); err != nil {
		t.Fatal(err)
	}
	return l
}

func TestLabKeyFormats(t *testing.T) {
	l := loadLab(t)
	svc := l.Services["ssh-modern"]
	r := newRig(t, Limits{})
	alice := principaltest.User(1)
	dir := filepath.Join(l.RuntimeDir, "ssh", "client")
	names := []string{"ecdsa-p256", "ecdsa-p256-pem", "ecdsa-p384", "ecdsa-p521", "ed25519", "ed25519-encrypted", "rsa-3072", "rsa-3072-pem", "rsa-3072-pem-encrypted", "rsa-3072-pkcs8"}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			content, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			pubLine, err := os.ReadFile(filepath.Join(dir, name+".pub"))
			if err != nil {
				t.Fatal(err)
			}
			want, _, _, _, err := ssh.ParseAuthorizedKey(pubLine)
			if err != nil {
				t.Fatal(err)
			}
			var passphrase string
			if strings.HasSuffix(name, "-encrypted") {
				raw, err := os.ReadFile(filepath.Join(l.RuntimeDir, "secrets", "ssh-key-"+name+"-passphrase"))
				if err != nil {
					t.Fatal(err)
				}
				passphrase = strings.TrimSpace(string(raw))
			}
			grant := r.grant(alice, "key.upload", userTarget(alice))
			s, err := r.svc.Upload(as(alice), Upload{Name: name, Content: string(content), Passphrase: passphrase, Grant: grant})
			if err != nil {
				t.Fatal(err)
			}
			signer, err := r.svc.Signer(context.Background(), alice.UserID, s.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(signer.PublicKey().Marshal(), want.Marshal()) {
				t.Fatal("stored key has another public key")
			}
			if err := signIn(svc.Host, svc.Port, svc.Fingerprints, signer); err != nil {
				t.Fatalf("sign-in as keyuser: %v", err)
			}
		})
	}
}

func signIn(host string, port int, fingerprints map[string]string, signer ssh.Signer) error {
	known := make([]string, 0, len(fingerprints))
	for _, fp := range fingerprints {
		known = append(known, fp)
	}
	cfg := &ssh.ClientConfig{
		User: "keyuser",
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if !slices.Contains(known, ssh.FingerprintSHA256(key)) {
				return errors.New("unknown lab host key")
			}
			return nil
		},
		Timeout: 10 * time.Second,
	}
	c, err := ssh.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)), cfg)
	if err != nil {
		return err
	}
	return c.Close()
}
