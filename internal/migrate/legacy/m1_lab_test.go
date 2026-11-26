//go:build lab

// The lab test signs in to the shared test lab (tests/lab) with keys and
// a host key that went through the M1 migration. Run it with
//
//	WEBSSH_LAB_JSON=<runtime>/lab.json go test -tags lab -run Lab ./internal/migrate/legacy
//
// It fails, not skips, when the lab is not reachable.
package legacy

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	json "encoding/json/v2"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/ssh/hostkey"
)

type m1Lab struct {
	RuntimeDir string `json:"runtime_dir"`
	Services   map[string]struct {
		Host         string            `json:"host"`
		Port         int               `json:"port"`
		Fingerprints map[string]string `json:"host_key_fingerprints"`
	} `json:"services"`
}

// fernetEncrypt writes a token as Python's cryptography.Fernet does, with
// the per-user key of app/key_encryption.py.
func fernetEncrypt(t *testing.T, secret string, userID int64, plain []byte) string {
	t.Helper()
	raw, err := pbkdf2.Key(sha256.New, sshKeyPurpose.password(secret, userID), []byte(sshKeyPurpose.salt), pbkdf2Iterations, 32)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(raw[16:])
	if err != nil {
		t.Fatal(err)
	}
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	padded := append(bytes.Clone(plain), bytes.Repeat([]byte{byte(pad)}, pad)...)
	iv := make([]byte, aes.BlockSize)
	_, _ = rand.Read(iv)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	msg := []byte{0x80}
	msg = binary.BigEndian.AppendUint64(msg, uint64(time.Now().Unix())) // #nosec G115 -- current time
	msg = append(append(msg, iv...), ct...)
	mac := hmac.New(sha256.New, raw[:16])
	mac.Write(msg)
	return base64.URLEncoding.EncodeToString(mac.Sum(msg))
}

func TestLabSignInWithMigratedKeysAndHostKey(t *testing.T) {
	path := os.Getenv("WEBSSH_LAB_JSON")
	if path == "" {
		path = filepath.Join("..", "..", "..", "tests", "lab", "runtime", "lab.json")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("lab not available (set WEBSSH_LAB_JSON): %v", err)
	}
	var lab m1Lab
	if err := json.Unmarshal(data, &lab); err != nil {
		t.Fatal(err)
	}
	svc := lab.Services["ssh-modern"]
	addr := net.JoinHostPort(svc.Host, strconv.Itoa(svc.Port))
	// The server's host key, checked against the lab's published
	// fingerprints, goes into the legacy known_hosts as Python stores it.
	var serverKey ssh.PublicKey
	probe := &ssh.ClientConfig{User: "nobody", Timeout: 10 * time.Second,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error { serverKey = key; return nil }}
	if c, err := ssh.Dial("tcp", addr, probe); err == nil {
		_ = c.Close()
	}
	if serverKey == nil {
		t.Fatal("no host key from the lab")
	}
	published := false
	for _, fp := range svc.Fingerprints {
		published = published || fp == ssh.FingerprintSHA256(serverKey)
	}
	if !published {
		t.Fatal("the lab presented an unpublished host key")
	}
	secret := golden.manifest.SecretKey.Value
	dir := copyGolden(t)
	const owner = 3
	appendTo(t, filepath.Join(dir, "users", "user_3", "known_hosts"),
		"[127.0.0.1]:"+strconv.Itoa(svc.Port)+" "+strings.TrimSpace(string(ssh.MarshalAuthorizedKey(serverKey)))+"\n")
	keys := map[string]bool{"ed25519": true, "ecdsa-p384": true, "rsa-3072-pem": false, "rsa-3072": true}
	var entries []string
	for name, encrypt := range keys {
		content, err := os.ReadFile(filepath.Join(lab.RuntimeDir, "ssh", "client", name))
		if err != nil {
			t.Fatal(err)
		}
		id := "1ab0" + strings.Repeat("0", 4) + "-0000-4000-8000-" + strconv.FormatInt(int64(len(entries)+100000000000), 10)
		file := string(content)
		if encrypt {
			file = fernetEncrypt(t, secret, owner, content)
		}
		writeLegacyFile(t, dir, "users/user_3/keys/"+id+".pem", file)
		entries = append(entries, `{"id": "`+id+`", "name": "lab `+name+`", "filename": "`+id+`.pem", "key_type": "lab", "encrypted": `+
			strconv.FormatBool(encrypt)+`, "uploaded_at": "2026-11-26T00:00:00"}`)
	}
	replaceIn(t, filepath.Join(dir, "users", "user_3", "keys", "keys.json"), `"keys": [`, `"keys": [`+strings.Join(entries, ",")+",")
	m := migrateM1(t, dir, secret, M1{})
	v := testVault(t, m)
	trust := hostkey.New(m.db, nil)
	for i := range entries {
		id := "1ab0" + strings.Repeat("0", 4) + "-0000-4000-8000-" + strconv.FormatInt(int64(i+100000000000), 10)
		signer, err := v.Signer(t.Context(), owner, id)
		if err != nil {
			t.Fatalf("key %d: %v", i, err)
		}
		cfg := &ssh.ClientConfig{User: "keyuser", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, Timeout: 10 * time.Second,
			HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
				ok, err := trust.Known(t.Context(), owner, "127.0.0.1", svc.Port, key)
				if err != nil || !ok {
					t.Errorf("the migrated host key was not trusted without a prompt: %v %v", ok, err)
					return errNotTrusted
				}
				return nil
			}}
		c, err := ssh.Dial("tcp", addr, cfg)
		if err != nil {
			t.Fatalf("key %d (%s): %v", i, signer.PublicKey().Type(), err)
		}
		sess, err := c.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		out, err := sess.Output("printf migrated")
		_ = c.Close()
		if err != nil || string(out) != "migrated" {
			t.Fatalf("key %d: %q, %v", i, out, err)
		}
	}
	if ok, _ := trust.Known(t.Context(), 1, "127.0.0.1", svc.Port, serverKey); ok {
		t.Fatal("another user trusts the host key without a prompt")
	}
}

var errNotTrusted = errorString("host key not trusted")

type errorString string

func (e errorString) Error() string { return string(e) }
