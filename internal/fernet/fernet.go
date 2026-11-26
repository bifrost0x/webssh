// Package fernet decrypts Fernet tokens as specified at
// https://github.com/fernet/spec (version 0x80).
//
// A token is the URL-safe base64 encoding (with padding) of
//
//	version (1 byte, 0x80) || timestamp (8 bytes, big endian, Unix seconds) ||
//	IV (16 bytes) || AES-128-CBC ciphertext (PKCS#7) || HMAC-SHA256 (32 bytes)
//
// The 32-byte key is the HMAC signing key (first half) followed by the AES
// encryption key (second half). The HMAC covers everything before it and is
// checked in constant time before any decryption.
//
// The package only decrypts. WebSSH reads Fernet tokens written by the Python
// release; new secrets use a different format.
package fernet

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	// KeySize is the length of a raw Fernet key.
	KeySize = 32

	version       = 0x80
	headerSize    = 1 + 8 + aes.BlockSize
	macSize       = sha256.Size
	minTokenBytes = headerSize + aes.BlockSize + macSize
	// maxClockSkew is the tolerance for timestamps in the future when a TTL
	// is enforced, as in the reference implementations.
	maxClockSkew = 60 * time.Second
)

// ErrInvalidToken reports a token that is malformed, was not produced with
// the key, or was altered. The cause is deliberately not distinguished.
var ErrInvalidToken = errors.New("fernet: invalid token")

// ErrExpired reports a token whose timestamp is outside the allowed window.
var ErrExpired = errors.New("fernet: token expired or from the future")

// Key holds the signing and encryption halves of a Fernet key.
type Key struct {
	signing    [16]byte
	encryption [16]byte
}

// NewKey returns a key from its 32 raw bytes.
func NewKey(raw []byte) (*Key, error) {
	if len(raw) != KeySize {
		return nil, fmt.Errorf("fernet: key must be %d bytes, got %d", KeySize, len(raw))
	}
	var k Key
	copy(k.signing[:], raw[:16])
	copy(k.encryption[:], raw[16:])
	return &k, nil
}

// ParseKey returns a key from its URL-safe base64 text form with padding,
// the form the Python library stores and exchanges.
func ParseKey(text string) (*Key, error) {
	raw, err := base64.URLEncoding.Strict().DecodeString(text)
	if err != nil {
		return nil, fmt.Errorf("fernet: key is not URL-safe base64: %w", err)
	}
	return NewKey(raw)
}

// Decrypt verifies the token and returns its plaintext. The timestamp is
// not checked, as in the Python release, which decrypts stored secrets
// without a TTL. Line breaks inside a token are ignored, as by
// encoding/base64 and Python's decoder; any other byte outside the
// URL-safe alphabet is rejected.
func (k *Key) Decrypt(token []byte) ([]byte, error) {
	plaintext, _, err := k.open(token)
	return plaintext, err
}

// DecryptWithTTL verifies the token and additionally rejects it when it is
// older than ttl or more than one minute in the future relative to now.
func (k *Key) DecryptWithTTL(token []byte, ttl time.Duration, now time.Time) ([]byte, error) {
	plaintext, issued, err := k.open(token)
	if err != nil {
		return nil, err
	}
	if issued.Add(ttl).Before(now) || now.Add(maxClockSkew).Before(issued) {
		return nil, ErrExpired
	}
	return plaintext, nil
}

// Timestamp returns the issue time of a token after verifying its HMAC.
func (k *Key) Timestamp(token []byte) (time.Time, error) {
	_, issued, err := k.open(token)
	return issued, err
}

func (k *Key) open(token []byte) ([]byte, time.Time, error) {
	raw := make([]byte, base64.URLEncoding.DecodedLen(len(token)))
	n, err := base64.URLEncoding.Strict().Decode(raw, token)
	if err != nil {
		return nil, time.Time{}, ErrInvalidToken
	}
	raw = raw[:n]
	if len(raw) < minTokenBytes || raw[0] != version {
		return nil, time.Time{}, ErrInvalidToken
	}
	body, tag := raw[:len(raw)-macSize], raw[len(raw)-macSize:]
	mac := hmac.New(sha256.New, k.signing[:])
	mac.Write(body)
	if !hmac.Equal(mac.Sum(nil), tag) {
		return nil, time.Time{}, ErrInvalidToken
	}
	ciphertext := body[headerSize:]
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, time.Time{}, ErrInvalidToken
	}
	block, err := aes.NewCipher(k.encryption[:])
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("fernet: %w", err)
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, body[9:headerSize]).CryptBlocks(plaintext, ciphertext)
	plaintext, ok := unpad(plaintext)
	if !ok {
		return nil, time.Time{}, ErrInvalidToken
	}
	// Python ignores the timestamp without a TTL, so an absurd value does
	// not invalidate the token; it is clamped and fails any TTL check.
	seconds := min(binary.BigEndian.Uint64(body[1:9]), 1<<62)
	return plaintext, time.Unix(int64(seconds), 0), nil // #nosec G115 -- clamped to 2^62 above
}

// unpad removes PKCS#7 padding. The HMAC has already authenticated the
// ciphertext, so the padding check cannot serve as a padding oracle.
func unpad(b []byte) ([]byte, bool) {
	if len(b) == 0 {
		return nil, false
	}
	n := int(b[len(b)-1])
	if n == 0 || n > aes.BlockSize || n > len(b) {
		return nil, false
	}
	if !bytes.Equal(b[len(b)-n:], bytes.Repeat([]byte{byte(n)}, n)) {
		return nil, false
	}
	return b[:len(b)-n], true
}
