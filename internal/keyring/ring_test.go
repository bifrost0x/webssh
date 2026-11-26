package keyring

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func seq(from, to byte) []byte {
	var b []byte
	for i := int(from); i <= int(to); i++ {
		b = append(b, byte(i))
	}
	return b
}

// TestDeriveRFC5869 checks the derivation against the SHA-256 test cases
// of RFC 5869, appendix A (IKM, salt, info, L, OKM).
func TestDeriveRFC5869(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		ikm, salt, info []byte
		okm             string
	}{
		{"A.1", bytes.Repeat([]byte{0x0b}, 22), seq(0x00, 0x0c), seq(0xf0, 0xf9),
			"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"},
		{"A.2", seq(0x00, 0x4f), seq(0x60, 0xaf), seq(0xb0, 0xff),
			"b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"},
		{"A.3", bytes.Repeat([]byte{0x0b}, 22), nil, nil,
			"8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"},
	}
	for _, tt := range tests {
		want := unhex(t, tt.okm)
		got, err := derive(tt.ikm, tt.salt, string(tt.info), len(want))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: OKM %x, want %x", tt.name, got, want)
		}
	}
}

// TestAEADOfficialVector opens test case 16 of the GCM specification
// (McGrew and Viega, AES-256, 96-bit IV, with additional data) through the
// AEAD the ring uses, whose input is nonce | ciphertext | tag.
func TestAEADOfficialVector(t *testing.T) {
	t.Parallel()
	key := unhex(t, "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
	nonce := unhex(t, "cafebabefacedbaddecaf888")
	plain := unhex(t, "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
	ad := unhex(t, "feedfacedeadbeeffeedfacedeadbeefabaddad2")
	ct := unhex(t, "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662")
	tag := unhex(t, "76fc6ece0f4e1768cddf8853bb2d551b")
	aead, err := newAEAD(key)
	if err != nil {
		t.Fatal(err)
	}
	in := append(append(bytes.Clone(nonce), ct...), tag...)
	got, err := aead.Open(nil, nil, in, ad)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("Open = %x, %v", got, err)
	}
	in[len(in)-1] ^= 1
	if _, err := aead.Open(nil, nil, in, ad); err == nil {
		t.Fatal("changed tag accepted")
	}
}

// Fixed inputs of the known-answer tests. The expected values are stored
// formats: a change here means existing databases no longer open.
var (
	katSecret   = []byte("kat-secret-key-not-used-anywhere")
	katMaterial = seq(0x20, 0x3f)
	katAAD      = AAD{Table: "vault_keys", Column: "private_key", Row: "7"}
)

const (
	katKeyID = "f007f482794fc739"
	katMAC   = "744fe45cb7273b39fbe77e51a67559c0228e6c4f61b774d4f5ab2af7d7583931"
	// katSealed is ring.Seal(SSHKey, katAAD, "kat plaintext") with the
	// nonce 000102030405060708090a0b.
	katSealed = "01f007f482794fc739000102030405060708090a0b6129e12a53614bca71b53624bb0d8bf1b18d9e10937da29887fd695bb2"
)

func katRing(t testing.TB) *Ring {
	t.Helper()
	r, err := Open(katSecret, katMaterial)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestDerivationFormat recomputes the keys from the documented info
// strings with crypto/hkdf directly, independently of Ring.
func TestDerivationFormat(t *testing.T) {
	t.Parallel()
	r := katRing(t)
	id, err := hkdf.Key(sha256.New, katSecret, katMaterial, "webssh-keyring-v1\x00key-id", 8)
	if err != nil {
		t.Fatal(err)
	}
	if r.KeyID() != hex.EncodeToString(id) {
		t.Fatalf("KeyID %s, want %x", r.KeyID(), id)
	}
	if r.KeyID() != katKeyID {
		t.Errorf("KeyID %s, frozen %s", r.KeyID(), katKeyID)
	}
	macKey, err := hkdf.Key(sha256.New, katSecret, katMaterial, "webssh-keyring-v1\x00mac\x00session_token", 32)
	if err != nil {
		t.Fatal(err)
	}
	m := hmac.New(sha256.New, macKey)
	m.Write([]byte("token"))
	if got := r.MAC(SessionToken, []byte("token")); !bytes.Equal(got, m.Sum(nil)) {
		t.Fatalf("MAC %x, want %x", got, m.Sum(nil))
	} else if hex.EncodeToString(got) != katMAC {
		t.Errorf("MAC %x, frozen %s", got, katMAC)
	}
}

// independentSeal builds a sealed value from the documented format with a
// fixed nonce, using only the standard library.
func independentSeal(t testing.TB, p Purpose, ad AAD, nonce, plain []byte) []byte {
	t.Helper()
	key, err := hkdf.Key(sha256.New, katSecret, katMaterial, "webssh-keyring-v1\x00seal\x00"+string(p), 32)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	header := append([]byte{1}, unhex(t, katKeyID)...)
	enc := "webssh-aad-v1\x00" + string(p) + "\x00" + ad.Table + "\x00" + ad.Column + "\x00" + ad.Row
	out := append(bytes.Clone(header), nonce...)
	return gcm.Seal(out, nonce, plain, append(bytes.Clone(header), enc...))
}

func TestSealFormat(t *testing.T) {
	t.Parallel()
	r := katRing(t)
	sealed := independentSeal(t, SSHKey, katAAD, seq(0, 11), []byte("kat plaintext"))
	if hex.EncodeToString(sealed) != katSealed {
		t.Errorf("sealed %x, frozen %s", sealed, katSealed)
	}
	got, err := r.Open(SSHKey, katAAD, sealed)
	if err != nil || string(got) != "kat plaintext" {
		t.Fatalf("Open = %q, %v", got, err)
	}
	own, err := r.Seal(SSHKey, katAAD, []byte("kat plaintext"))
	if err != nil {
		t.Fatal(err)
	}
	if len(own) != len(sealed) || !bytes.Equal(own[:headerSize], sealed[:headerSize]) {
		t.Fatalf("Seal layout %x, want header %x and length %d", own, sealed[:headerSize], len(sealed))
	}
	again, err := r.Seal(SSHKey, katAAD, []byte("kat plaintext"))
	if err != nil || bytes.Equal(own, again) {
		t.Fatal("two seals of the same plaintext are equal (nonce reused)")
	}
}

func TestOpenRejects(t *testing.T) {
	t.Parallel()
	r := katRing(t)
	plain := []byte("-----BEGIN OPENSSH PRIVATE KEY-----")
	sealed, err := r.Seal(SSHKey, katAAD, plain)
	if err != nil {
		t.Fatal(err)
	}
	otherSecret, err := Open([]byte("another-secret"), katMaterial)
	if err != nil {
		t.Fatal(err)
	}
	otherMaterial, err := Open(katSecret, seq(0x40, 0x5f))
	if err != nil {
		t.Fatal(err)
	}
	flip := func(i int) []byte {
		b := bytes.Clone(sealed)
		b[i] ^= 0x01
		return b
	}
	tests := []struct {
		name   string
		ring   *Ring
		p      Purpose
		ad     AAD
		sealed []byte
		want   error
	}{
		{"other row", r, SSHKey, AAD{"vault_keys", "private_key", "8"}, sealed, ErrDecrypt},
		{"other column", r, SSHKey, AAD{"vault_keys", "public_key", "7"}, sealed, ErrDecrypt},
		{"other table", r, SSHKey, AAD{"totp_secrets", "private_key", "7"}, sealed, ErrDecrypt},
		{"other purpose", r, TOTP, katAAD, sealed, ErrDecrypt},
		{"wrong SECRET_KEY", otherSecret, SSHKey, katAAD, sealed, ErrWrongKey},
		{"wrong material", otherMaterial, SSHKey, katAAD, sealed, ErrWrongKey},
		{"changed version", r, SSHKey, katAAD, flip(0), ErrFormat},
		{"changed key id", r, SSHKey, katAAD, flip(3), ErrWrongKey},
		{"changed nonce", r, SSHKey, katAAD, flip(headerSize + 2), ErrDecrypt},
		{"changed ciphertext", r, SSHKey, katAAD, flip(headerSize + nonceSize + 1), ErrDecrypt},
		{"changed tag", r, SSHKey, katAAD, flip(len(sealed) - 1), ErrDecrypt},
		{"truncated", r, SSHKey, katAAD, sealed[:MinSealedSize-1], ErrFormat},
		{"tag cut off", r, SSHKey, katAAD, sealed[:len(sealed)-tagSize], ErrDecrypt},
		{"empty", r, SSHKey, katAAD, nil, ErrFormat},
		{"empty row", r, SSHKey, AAD{"vault_keys", "private_key", ""}, sealed, ErrAAD},
		{"browser scope purpose", r, BrowserScope, katAAD, sealed, ErrPurpose},
		{"unknown purpose", r, Purpose("ssh_keys"), katAAD, sealed, ErrPurpose},
	}
	for _, tt := range tests {
		got, err := tt.ring.Open(tt.p, tt.ad, tt.sealed)
		if !errors.Is(err, tt.want) || got != nil {
			t.Errorf("%s: Open = %q, %v; want %v", tt.name, got, err, tt.want)
		}
	}
}

func TestWrongKeyMessageIsClear(t *testing.T) {
	t.Parallel()
	r := katRing(t)
	if err := r.Verify(katKeyID); err != nil {
		t.Fatal(err)
	}
	err := r.Verify("0011223344556677")
	if !errors.Is(err, ErrKeyMismatch) || !strings.Contains(err.Error(), "SECRET_KEY") {
		t.Fatalf("Verify = %v", err)
	}
	if !strings.Contains(ErrWrongKey.Error(), "SECRET_KEY") {
		t.Fatal("ErrWrongKey does not name SECRET_KEY")
	}
	if s := r.String(); strings.Contains(s, hex.EncodeToString(katSecret)) || !strings.Contains(s, katKeyID) {
		t.Fatalf("String = %q", s)
	}
}

func TestOpenRing(t *testing.T) {
	t.Parallel()
	if _, err := Open(nil, katMaterial); !errors.Is(err, ErrSecret) {
		t.Errorf("empty secret: %v", err)
	}
	for _, n := range []int{0, 31, 33} {
		if _, err := Open(katSecret, make([]byte, n)); !errors.Is(err, ErrMaterialSize) {
			t.Errorf("material of %d bytes: %v", n, err)
		}
	}
	// The ring keeps its own copies of its inputs.
	secret, material := bytes.Clone(katSecret), bytes.Clone(katMaterial)
	r, err := Open(secret, material)
	if err != nil {
		t.Fatal(err)
	}
	clear(secret)
	clear(material)
	if r.KeyID() != katKeyID || r.BrowserScope(1, "a", "b") != katRing(t).BrowserScope(1, "a", "b") {
		t.Fatal("ring changed with its inputs")
	}
}

func TestPurposeKeysAreIndependent(t *testing.T) {
	t.Parallel()
	r := katRing(t)
	if len(sealPurposes)+len(macPurposes)+1 != len(Purposes()) {
		t.Fatal("a purpose has no operation")
	}
	seen := map[string]Purpose{}
	for _, p := range macPurposes {
		mac := hex.EncodeToString(r.MAC(p, []byte("m")))
		if q, dup := seen[mac]; dup {
			t.Errorf("%s and %s share a MAC key", p, q)
		}
		seen[mac] = p
	}
	for _, p := range sealPurposes {
		sealed, err := r.Seal(p, katAAD, []byte("x"))
		if err != nil {
			t.Fatal(err)
		}
		for _, q := range sealPurposes {
			if q != p {
				if _, err := r.Open(q, katAAD, sealed); !errors.Is(err, ErrDecrypt) {
					t.Errorf("%s value opened as %s: %v", p, q, err)
				}
			}
		}
	}
}

func TestPurposeOperations(t *testing.T) {
	t.Parallel()
	r := katRing(t)
	for _, p := range append([]Purpose{BrowserScope, "other"}, sealPurposes...) {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("MAC(%q) did not panic", p)
				}
			}()
			r.MAC(p, nil)
		}()
	}
	for _, p := range append([]Purpose{BrowserScope, "other"}, macPurposes...) {
		if _, err := r.Seal(p, katAAD, nil); !errors.Is(err, ErrPurpose) {
			t.Errorf("Seal(%q): %v", p, err)
		}
		if _, err := r.Open(p, katAAD, unhex(t, katSealed)); !errors.Is(err, ErrPurpose) {
			t.Errorf("Open(%q): %v", p, err)
		}
	}
}

func TestFormattingRevealsNoKey(t *testing.T) {
	t.Parallel()
	r := katRing(t)
	var logged bytes.Buffer
	slog.New(slog.NewTextHandler(&logged, nil)).Info("ring", "ring", r)
	outputs := []string{logged.String()}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		outputs = append(outputs, fmt.Sprintf(verb, r))
	}
	for _, out := range outputs {
		for _, secret := range [][]byte{katSecret, katMaterial} {
			for _, form := range []string{string(secret), hex.EncodeToString(secret), fmt.Sprint(secret)} {
				if strings.Contains(out, form) {
					t.Errorf("output %q contains key material", out)
				}
			}
		}
		if !strings.Contains(out, katKeyID) {
			t.Errorf("output %q does not name the key", out)
		}
	}
}
