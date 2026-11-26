package keyring

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
)

// Stored formats. The info strings are part of every derived key and the
// header is part of every ciphertext; they never change. A new format gets
// a new version and both versions are read until every record is resealed.
const (
	infoPrefix = "webssh-keyring-v1\x00"
	infoSeal   = infoPrefix + "seal\x00" // + purpose: AES-256-GCM key
	infoMAC    = infoPrefix + "mac\x00"  // + purpose: HMAC-SHA256 key
	infoKeyID  = infoPrefix + "key-id"   // key identifier

	// MaterialSize is the length of the keyring material in bytes.
	MaterialSize = 32

	sealVersion byte = 1
	keyIDSize        = 8
	headerSize       = 1 + keyIDSize
	nonceSize        = 12
	tagSize          = 16
	// MinSealedSize is the length of a sealed empty plaintext.
	MinSealedSize = headerSize + nonceSize + tagSize
)

// Errors of Open and Ring.Open. Callers match them with errors.Is.
var (
	// ErrSecret reports an empty SECRET_KEY.
	ErrSecret = errors.New("keyring: SECRET_KEY is empty")
	// ErrMaterialSize reports keyring material of the wrong length.
	ErrMaterialSize = fmt.Errorf("keyring: material must be %d bytes", MaterialSize)
	// ErrFormat reports a value that is not a sealed record of a known
	// format version (truncated, or not sealed by the keyring).
	ErrFormat = errors.New("keyring: not a sealed value of a known format")
	// ErrWrongKey reports a value sealed under another SECRET_KEY or other
	// keyring material than the ring's.
	ErrWrongKey = errors.New("keyring: the value was sealed with a different SECRET_KEY or keyring material")
	// ErrDecrypt reports a value whose authentication failed: it was
	// changed, or it belongs to another record or purpose.
	ErrDecrypt = errors.New("keyring: the sealed value is damaged or belongs to another record")
	// ErrKeyMismatch reports that the ring does not match the key
	// identifier stored in the database (state S9 of the migration
	// specification).
	ErrKeyMismatch = errors.New("keyring: SECRET_KEY or the keyring material does not match the database; " +
		"sealed SSH keys, saved passwords and second factors cannot be read")
	// ErrPurpose reports a purpose that is unknown or not valid for the
	// operation.
	ErrPurpose = errors.New("keyring: purpose not valid for this operation")
)

// Ring holds the subkeys derived from one SECRET_KEY and one keyring
// material. It is immutable and safe for concurrent use.
type Ring struct {
	seal     map[Purpose]cipher.AEAD
	mac      map[Purpose][]byte
	id       [keyIDSize]byte
	secret   []byte // only for the browser-local namespace (BrowserScope)
	material [MaterialSize]byte
}

// derive is HKDF-SHA256 (RFC 5869) with SECRET_KEY as input key material
// and the keyring material as salt, so that neither alone yields a key.
func derive(secret, material []byte, info string, n int) ([]byte, error) {
	k, err := hkdf.Key(sha256.New, secret, material, info, n)
	if err != nil {
		return nil, fmt.Errorf("keyring: derive: %w", err)
	}
	return k, nil
}

// newAEAD returns AES-256-GCM with random 96-bit nonces: Seal prepends the
// nonce, Open reads it from the front.
func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("keyring: cipher: %w", err)
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, fmt.Errorf("keyring: cipher: %w", err)
	}
	return aead, nil
}

// Each purpose has one operation: Seal and Open for secrets stored
// encrypted, MAC for tokens stored only in their MAC form. BrowserScope
// names the separate browser-local namespace derivation and has no keyring
// key.
var (
	sealPurposes = []Purpose{SSHKey, TOTP, WebAuthnChallenge}
	macPurposes  = []Purpose{SessionToken, CSRF, StepUpGrant}
)

// Open derives the ring from SECRET_KEY (as the bytes of the configured
// string) and the keyring material. It does not read any file.
func Open(secret, material []byte) (*Ring, error) {
	if len(secret) == 0 {
		return nil, ErrSecret
	}
	if len(material) != MaterialSize {
		return nil, ErrMaterialSize
	}
	r := &Ring{
		seal:   make(map[Purpose]cipher.AEAD, len(purposes)),
		mac:    make(map[Purpose][]byte, len(purposes)),
		secret: bytes.Clone(secret),
	}
	copy(r.material[:], material)
	id, err := derive(secret, material, infoKeyID, keyIDSize)
	if err != nil {
		return nil, err
	}
	copy(r.id[:], id)
	for _, p := range sealPurposes {
		sk, err := derive(secret, material, infoSeal+string(p), 32)
		if err != nil {
			return nil, err
		}
		if r.seal[p], err = newAEAD(sk); err != nil {
			return nil, err
		}
	}
	for _, p := range macPurposes {
		if r.mac[p], err = derive(secret, material, infoMAC+string(p), 32); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// KeyID identifies the ring's keys (16 lower-case hex digits). The database
// stores it; every sealed value carries it. It reveals nothing about the
// keys without the material.
func (r *Ring) KeyID() string { return hex.EncodeToString(r.id[:]) }

// String names the ring by its key identifier and never prints key bytes.
func (r *Ring) String() string { return "keyring.Ring(" + r.KeyID() + ")" }

// Format prints String for every verb, including %#v and %+v, so that no
// formatting of a ring reveals SECRET_KEY, the material or a key.
func (r *Ring) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, r.String()) }

// LogValue logs the ring as its key identifier.
func (r *Ring) LogValue() slog.Value { return slog.StringValue(r.String()) }

// Verify compares the ring with the key identifier stored in the database.
// A mismatch is ErrKeyMismatch; Go must not start then (state S9).
func (r *Ring) Verify(storedKeyID string) error {
	if storedKeyID != r.KeyID() {
		return fmt.Errorf("%w (database key %q, current key %q)", ErrKeyMismatch, storedKeyID, r.KeyID())
	}
	return nil
}

// additionalData is the GCM additional data: the header followed by the
// encoded AAD, so version, key identifier, purpose and record are all
// authenticated.
func additionalData(header []byte, p Purpose, ad AAD) ([]byte, error) {
	enc, err := ad.Bytes(p)
	if err != nil {
		return nil, err
	}
	return append(bytes.Clone(header), enc...), nil
}

// Seal encrypts plain for the record ad; only the seal purposes (SSHKey,
// TOTP, WebAuthnChallenge) are accepted. The result is
// version (1) | key id (8) | nonce (12) | ciphertext | tag (16).
func (r *Ring) Seal(p Purpose, ad AAD, plain []byte) ([]byte, error) {
	if r.seal[p] == nil {
		return nil, ErrPurpose
	}
	header := append([]byte{sealVersion}, r.id[:]...)
	aad, err := additionalData(header, p, ad)
	if err != nil {
		return nil, err
	}
	return r.seal[p].Seal(header, nil, plain, aad), nil // #nosec G407 -- NewGCMWithRandomNonce draws the nonce; it takes none
}

// Open decrypts a value sealed for the record ad. It fails with ErrFormat,
// ErrWrongKey or ErrDecrypt and never returns partial plaintext.
func (r *Ring) Open(p Purpose, ad AAD, sealed []byte) ([]byte, error) {
	if r.seal[p] == nil {
		return nil, ErrPurpose
	}
	if len(sealed) < MinSealedSize || sealed[0] != sealVersion {
		return nil, ErrFormat
	}
	if subtle.ConstantTimeCompare(sealed[1:headerSize], r.id[:]) != 1 {
		return nil, ErrWrongKey
	}
	aad, err := additionalData(sealed[:headerSize], p, ad)
	if err != nil {
		return nil, err
	}
	plain, err := r.seal[p].Open(nil, nil, sealed[headerSize:], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plain, nil
}

// MAC returns HMAC-SHA256 of msg under the purpose's MAC key (32 bytes);
// only the MAC purposes (SessionToken, CSRF, StepUpGrant) have one.
// Stored tokens are kept only in this form. Compare MACs with hmac.Equal.
// Purposes are constants; an unknown one is a programming error and
// panics.
func (r *Ring) MAC(p Purpose, msg []byte) []byte {
	if r.mac[p] == nil {
		panic(fmt.Sprintf("keyring: MAC with purpose %q", p))
	}
	m := hmac.New(sha256.New, r.mac[p])
	m.Write(msg)
	return m.Sum(nil)
}
