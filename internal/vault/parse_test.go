package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Every key the Python release stored loads with the same public key and
// key type.
func TestParseGoldenStoredKeys(t *testing.T) {
	stored, _ := goldenKeys(t)
	for _, k := range stored {
		t.Run(k.Label, func(t *testing.T) {
			got, err := parseKey(k.pem(t), nil)
			if err != nil {
				t.Fatal(err)
			}
			want, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k.Public))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.signer.PublicKey().Marshal(), want.Marshal()) {
				t.Error("public key differs from the Python release")
			}
			if got.keyType != k.KeyType {
				t.Errorf("type %s, Python %s", got.keyType, k.KeyType)
			}
			if !bytes.Equal(got.stored, k.pem(t)) {
				t.Error("an unencrypted key must be stored as uploaded")
			}
		})
	}
}

// Keys the Python release refused: plain PKCS#8 loads now (K2), protected
// OpenSSH and PEM keys load with their passphrase and are stored without
// it, encrypted PKCS#8 is refused with its own reason.
func TestParseGoldenRejectedKeys(t *testing.T) {
	_, rejected := goldenKeys(t)
	if len(rejected) == 0 {
		t.Fatal("no rejected keys in the golden data set")
	}
	for _, k := range rejected {
		t.Run(k.Label, func(t *testing.T) {
			raw := k.pem(t)
			_, err := parseKey(raw, nil)
			switch {
			case k.Format == "pkcs8" && !k.Protected:
				if err != nil {
					t.Fatalf("plain PKCS#8: %v", err)
				}
				return
			case k.Format == "pkcs8":
				if !errors.Is(err, errEncryptedPKCS8) {
					t.Fatalf("encrypted PKCS#8: %v", err)
				}
				if _, err := parseKey(raw, []byte(goldenPassphrase)); !errors.Is(err, errEncryptedPKCS8) {
					t.Fatalf("encrypted PKCS#8 with passphrase: %v", err)
				}
				return
			}
			if !errors.Is(err, errPassphraseMissing) {
				t.Fatalf("without passphrase: %v", err)
			}
			if _, err := parseKey(raw, []byte("wrong passphrase")); !errors.Is(err, errPassphraseWrong) {
				t.Fatalf("wrong passphrase: %v", err)
			}
			got, err := parseKey(raw, []byte(goldenPassphrase))
			if err != nil {
				t.Fatalf("with passphrase: %v", err)
			}
			if got.keyType != k.Algorithm {
				t.Errorf("type %s, want %s", got.keyType, k.Algorithm)
			}
			// The stored form opens without any passphrase.
			signer, _, err := signerOf(got.stored)
			if err != nil {
				t.Fatalf("stored form: %v", err)
			}
			if !bytes.Equal(signer.PublicKey().Marshal(), got.signer.PublicKey().Marshal()) {
				t.Error("stored form has another public key")
			}
			if bytes.Contains(got.stored, []byte("ENCRYPTED")) || bytes.Contains(got.stored, []byte("bcrypt")) {
				t.Error("stored form is still encrypted")
			}
		})
	}
}

// A passphrase given for an unencrypted key is ignored, the key loads.
func TestParsePassphraseForPlainKey(t *testing.T) {
	plain := newEd25519PEM(t)
	got, err := parseKey(plain, []byte("unused"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.stored, plain) {
		t.Error("plain key must be stored as uploaded")
	}
}

func TestParseRejects(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der := x509.MarshalPKCS1PrivateKey(rsaKey)
	dsaOpenSSH := openSSHContainer(t, "ssh-dss", "none", nil)
	cases := map[string]struct {
		in   []byte
		want error
	}{
		"empty":           {nil, errKeyInvalid},
		"garbage":         {[]byte("not a key"), errKeyInvalid},
		"public key":      {[]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"), errKeyInvalid},
		"oversized":       {append(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}), bytes.Repeat([]byte("x"), MaxKeyBytes)...), errKeyInvalid},
		"dsa pem":         {[]byte("-----BEGIN DSA PRIVATE KEY-----\nAAAA\n-----END DSA PRIVATE KEY-----\n"), errKeyDSA},
		"dsa openssh":     {pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: dsaOpenSSH}), errKeyDSA},
		"broken openssh":  {pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: []byte("openssh-key-v1\x00\x00")}), errKeyInvalid},
		"encrypted pkcs8": {pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{0x30, 0}}), errEncryptedPKCS8},
		"unknown block":   {pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x30, 0}}), errKeyInvalid},
	}
	for name, c := range cases {
		if _, err := parseKey(c.in, nil); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	// Python accepted this size exactly; one byte more is refused.
	if _, err := parseKey(bytes.Repeat([]byte("a"), MaxKeyBytes+1), nil); !errors.Is(err, errKeyInvalid) {
		t.Errorf("over limit: %v", err)
	}
}

// The bcrypt rounds of a protected OpenSSH key are bounded before the KDF
// runs: a key claiming a huge number of rounds is refused at once.
func TestParseBoundsKDFRounds(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseKey(pem.EncodeToMemory(block), []byte("secret")); err != nil {
		t.Fatalf("default rounds: %v", err)
	}
	for _, rounds := range []uint32{maxKDFRounds + 1, 1 << 31} {
		patched := withRounds(t, block.Bytes, rounds)
		if _, err := parseKey(pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: patched}), []byte("secret")); !errors.Is(err, errKDFRounds) {
			t.Errorf("rounds %d: %v", rounds, err)
		}
	}
}

// withRounds rewrites the bcrypt rounds in an OpenSSH container.
func withRounds(t *testing.T, data []byte, rounds uint32) []byte {
	t.Helper()
	out := bytes.Clone(data)
	rest := out[len("openssh-key-v1\x00"):]
	_, rest, _ = readString(rest) // cipher
	_, rest, _ = readString(rest) // kdf name
	opts, _, ok := readString(rest)
	if !ok {
		t.Fatal("no KDF options")
	}
	_, r, ok := readString(opts) // salt
	if !ok || len(r) < 4 {
		t.Fatal("no rounds")
	}
	binary.BigEndian.PutUint32(r, rounds)
	return out
}

// openSSHContainer builds the unencrypted header of an OpenSSH container
// with one public key of the given type.
func openSSHContainer(t *testing.T, keyType, kdf string, kdfOptions []byte) []byte {
	t.Helper()
	str := func(b []byte) []byte {
		return append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...)
	}
	var b []byte
	b = append(b, "openssh-key-v1\x00"...)
	b = append(b, str([]byte("none"))...)
	b = append(b, str([]byte(kdf))...)
	b = append(b, str(kdfOptions)...)
	b = binary.BigEndian.AppendUint32(b, 1)
	b = append(b, str(str([]byte(keyType)))...)
	return b
}

func TestInspectOpenSSH(t *testing.T) {
	info, ok := inspectOpenSSH(openSSHContainer(t, "ssh-ed25519", "none", nil))
	if !ok || info.keyType != "ssh-ed25519" || info.rounds != 0 {
		t.Fatalf("%+v %v", info, ok)
	}
	opts := append(binary.BigEndian.AppendUint32(nil, 4), "salt"...)
	opts = binary.BigEndian.AppendUint32(opts, 42)
	info, ok = inspectOpenSSH(openSSHContainer(t, "ssh-rsa", "bcrypt", opts))
	if !ok || info.rounds != 42 {
		t.Fatalf("%+v %v", info, ok)
	}
	for _, bad := range [][]byte{nil, []byte("openssh-key-v1"), []byte("openssh-key-v1\x00\xff\xff\xff\xff"), openSSHContainer(t, "x", "bcrypt", []byte{0, 0})} {
		if _, ok := inspectOpenSSH(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
}

// FuzzParseKey: arbitrary uploads never panic, and whatever loads has a
// stored form that loads to the same public key without a passphrase.
func FuzzParseKey(f *testing.F) {
	stored, rejected := goldenKeys(f)
	for _, k := range append(stored, rejected...) {
		f.Add(k.pem(f), []byte(goldenPassphrase))
	}
	f.Add(newEd25519PEM(f), []byte(nil))
	f.Add([]byte("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n-----END OPENSSH PRIVATE KEY-----\n"), []byte("x"))
	f.Fuzz(func(t *testing.T, content, passphrase []byte) {
		if len(passphrase) > MaxPassphraseBytes {
			return
		}
		got, err := parseKey(content, passphrase)
		if err != nil {
			return
		}
		signer, keyType, err := signerOf(got.stored)
		if err != nil {
			t.Fatalf("stored form does not load: %v", err)
		}
		if keyType != got.keyType || !bytes.Equal(signer.PublicKey().Marshal(), got.signer.PublicKey().Marshal()) {
			t.Fatal("stored form differs")
		}
	})
}
