package fernet

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

// Official vectors from https://github.com/fernet/spec at commit
// 20dead475f53f11d20592baf29ad697163afc0cd (generate.json, verify.json,
// invalid.json).
const specSecret = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4="

const specToken = "gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA=="

func specTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func specKey(t *testing.T) *Key {
	t.Helper()
	key, err := ParseKey(specSecret)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// seal builds a token exactly as the specification describes. It exists
// only to check the generate vector and to produce fuzz seeds.
func seal(key *Key, iv []byte, issued time.Time, msg []byte) []byte {
	block, _ := aes.NewCipher(key.encryption[:])
	pad := aes.BlockSize - len(msg)%aes.BlockSize
	padded := append(bytes.Clone(msg), bytes.Repeat([]byte{byte(pad)}, pad)...)
	body := make([]byte, headerSize, headerSize+len(padded)+macSize)
	body[0] = version
	binary.BigEndian.PutUint64(body[1:9], uint64(issued.Unix()))
	copy(body[9:], iv)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	body = append(body, ciphertext...)
	mac := hmac.New(sha256.New, key.signing[:])
	mac.Write(body)
	return []byte(base64.URLEncoding.EncodeToString(mac.Sum(body)))
}

func TestGenerateVector(t *testing.T) {
	t.Parallel()
	key := specKey(t)
	iv := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	got := seal(key, iv, specTime(t, "1985-10-26T01:20:00-07:00"), []byte("hello"))
	if string(got) != specToken {
		t.Fatalf("seal = %s, want %s", got, specToken)
	}
	plain, err := key.Decrypt(got)
	if err != nil || string(plain) != "hello" {
		t.Fatalf("Decrypt = %q, %v", plain, err)
	}
}

func TestVerifyVector(t *testing.T) {
	t.Parallel()
	key := specKey(t)
	plain, err := key.DecryptWithTTL([]byte(specToken), 60*time.Second, specTime(t, "1985-10-26T01:20:01-07:00"))
	if err != nil || string(plain) != "hello" {
		t.Fatalf("DecryptWithTTL = %q, %v", plain, err)
	}
	issued, err := key.Timestamp([]byte(specToken))
	if err != nil || !issued.Equal(specTime(t, "1985-10-26T01:20:00-07:00")) {
		t.Fatalf("Timestamp = %v, %v", issued, err)
	}
}

func TestInvalidVectors(t *testing.T) {
	t.Parallel()
	const now = "1985-10-26T01:20:01-07:00"
	tests := []struct {
		name  string
		token string
		now   string
		want  error
	}{
		{"incorrect mac", "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAl1-szkFVzXTuGb4hR8AKtwcaX1YdykQUFBQUFBQUFBQQ==", now, ErrInvalidToken},
		{"too short", "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPA==", now, ErrInvalidToken},
		{"invalid base64", "%%%%%%%%%%%%%AECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAl1-szkFVzXTuGb4hR8AKtwcaX1YdykRtfsH-p1YsUD2Q==", now, ErrInvalidToken},
		{"payload size not multiple of block size", "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPOm73QeoCk9uGib28Xe5vz6oxq5nmxbx_v7mrfyudzUm", now, ErrInvalidToken},
		{"payload padding error", "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0ODz4LEpdELGQAad7aNEHbf-JkLPIpuiYRLQ3RtXatOYREu2FWke6CnJNYIbkuKNqOhw==", now, ErrInvalidToken},
		{"far-future TS (unacceptable clock skew)", "gAAAAAAdwStRAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAnja1xKYyhd-Y6mSkTOyTGJmw2Xc2a6kBd-iX9b_qXQcw==", now, ErrExpired},
		{"expired TTL", "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAl1-szkFVzXTuGb4hR8AKtwcaX1YdykRtfsH-p1YsUD2Q==", "1985-10-26T01:21:31-07:00", ErrExpired},
		{"incorrect IV (causes padding error)", "gAAAAAAdwJ6xBQECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAkLhFLHpGtDBRLRTZeUfWgHSv49TF2AUEZ1TIvcZjK1zQ==", now, ErrInvalidToken},
	}
	key := specKey(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := key.DecryptWithTTL([]byte(tt.token), 60*time.Second, specTime(t, tt.now))
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestKeyErrors(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, text string }{
		{"short", base64.URLEncoding.EncodeToString(make([]byte, 31))},
		{"long", base64.URLEncoding.EncodeToString(make([]byte, 33))},
		{"standard alphabet", "cw/0x689RpI+jtRR7oE8h/eQsKImvJapLeSbXpwF4e4="},
		{"unpadded", "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseKey(tt.text); err == nil {
				t.Fatal("ParseKey accepted an invalid key")
			}
		})
	}
}

// Every single-byte change of a valid token is rejected.
func TestEveryByteFlipIsRejected(t *testing.T) {
	t.Parallel()
	key := specKey(t)
	raw, _ := base64.URLEncoding.DecodeString(specToken)
	for i := range raw {
		changed := bytes.Clone(raw)
		changed[i] ^= 0x01
		token := []byte(base64.URLEncoding.EncodeToString(changed))
		if _, err := key.Decrypt(token); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("byte %d: err = %v", i, err)
		}
	}
}

// Round trip for random keys and messages of every length around block
// boundaries: what seal produces, Decrypt returns, and a different key fails.
func TestRoundTripProperty(t *testing.T) {
	t.Parallel()
	for size := range 70 {
		raw, other := make([]byte, KeySize), make([]byte, KeySize)
		msg, iv := make([]byte, size), make([]byte, aes.BlockSize)
		for _, b := range [][]byte{raw, other, msg, iv} {
			_, _ = rand.Read(b)
		}
		key, _ := NewKey(raw)
		wrong, _ := NewKey(other)
		token := seal(key, iv, time.Unix(1_700_000_000, 0), msg)
		got, err := key.Decrypt(token)
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("size %d: Decrypt = %x, %v", size, got, err)
		}
		if _, err := wrong.Decrypt(token); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("size %d: wrong key err = %v", size, err)
		}
	}
}

func FuzzDecrypt(f *testing.F) {
	key, err := ParseKey(specSecret)
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(specToken))
	f.Add([]byte("gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPA=="))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, token []byte) {
		plain, err := key.Decrypt(token)
		if err != nil {
			if !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("unexpected error kind: %v", err)
			}
			return
		}
		// An accepted token is exactly the canonical encoding of its
		// timestamp, IV and plaintext under the key: nothing else decrypts.
		// encoding/base64 skips CR and LF; Python's non-validating decoder
		// skips them too, so they are the only tolerated difference.
		token = bytes.ReplaceAll(bytes.ReplaceAll(token, []byte("\r"), nil), []byte("\n"), nil)
		raw, decodeErr := base64.URLEncoding.DecodeString(string(token))
		if decodeErr != nil {
			t.Fatalf("accepted undecodable token: %v", decodeErr)
		}
		issued := time.Unix(int64(binary.BigEndian.Uint64(raw[1:9])), 0)
		if again := seal(key, raw[9:headerSize], issued, plain); !bytes.Equal(again, token) {
			t.Fatalf("accepted non-canonical token %q", token)
		}
	})
}
