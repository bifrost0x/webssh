package legacy

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"math/big"
)

// COSE algorithm identifiers the Python release registers (py_webauthn
// default list): EdDSA, ES256 and RS256.
const (
	COSEAlgEdDSA int64 = -8
	COSEAlgES256 int64 = -7
	COSEAlgRS256 int64 = -257
)

// Passkey is one row of webauthn_credentials with its parsed COSE key.
type Passkey struct {
	ID           int64
	UserID       int64
	CredentialID []byte
	// COSEKey is the stored COSE_Key, unchanged. The migration keeps these
	// bytes; PublicKey and Algorithm prove they parse.
	COSEKey    []byte
	Algorithm  int64
	PublicKey  crypto.PublicKey // *ecdsa.PublicKey, *rsa.PublicKey or ed25519.PublicKey
	SignCount  int64
	Transports []string
	Name       string
	CreatedAt  string
}

// Passkeys reads every WebAuthn credential and parses its public key.
func (s *Source) Passkeys(ctx context.Context) ([]Passkey, error) {
	if !s.schema.HasTable("webauthn_credentials") {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, user_id, credential_id, public_key, sign_count, transports, name,
		CAST(created_at AS TEXT) FROM webauthn_credentials ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("legacy: read passkeys: %w", err)
	}
	defer rows.Close()
	var out []Passkey
	for rows.Next() {
		var p Passkey
		var transports string
		if err := rows.Scan(&p.ID, &p.UserID, &p.CredentialID, &p.COSEKey, &p.SignCount, &transports, &p.Name, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("legacy: read passkeys: %w", err)
		}
		if err := json.Unmarshal([]byte(transports), &p.Transports); err != nil {
			return nil, fmt.Errorf("legacy: passkey %d: transports: %w", p.ID, err)
		}
		if p.PublicKey, p.Algorithm, err = ParseCOSEKey(p.COSEKey); err != nil {
			return nil, fmt.Errorf("legacy: passkey %d: %w", p.ID, err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// COSE key parameters (RFC 9052 section 7, RFC 9053, RFC 8230).
const (
	coseKty    = 1
	coseAlg    = 3
	coseCrv    = -1 // EC2 and OKP
	coseX      = -2
	coseY      = -3
	coseRSAN   = -1
	coseRSAE   = -2
	ktyOKP     = 1
	ktyEC2     = 2
	ktyRSA     = 3
	crvP256    = 1
	crvEd25519 = 6
)

var errCOSE = errors.New("legacy: unsupported COSE key")

// ParseCOSEKey parses a COSE_Key of one of the three supported algorithms
// and checks that key type, curve and algorithm agree.
func ParseCOSEKey(data []byte) (crypto.PublicKey, int64, error) {
	v, err := decodeCBOR(data)
	if err != nil {
		return nil, 0, err
	}
	m, ok := v.(cborMap)
	if !ok {
		return nil, 0, fmt.Errorf("%w: not a map", errCOSE)
	}
	kty, okKty := m[int64(coseKty)].(int64)
	alg, okAlg := m[int64(coseAlg)].(int64)
	if !okKty || !okAlg {
		return nil, 0, fmt.Errorf("%w: missing kty or alg", errCOSE)
	}
	switch {
	case kty == ktyEC2 && alg == COSEAlgES256:
		x, y, err := coseBytes(m, coseX, 32), coseBytes(m, coseY, 32), coseCurve(m, crvP256)
		if x == nil || y == nil || err != nil {
			return nil, 0, fmt.Errorf("%w: malformed P-256 key", errCOSE)
		}
		key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			return nil, 0, fmt.Errorf("%w: %w", errCOSE, err)
		}
		return key, alg, nil
	case kty == ktyOKP && alg == COSEAlgEdDSA:
		x := coseBytes(m, coseX, ed25519.PublicKeySize)
		if x == nil || coseCurve(m, crvEd25519) != nil {
			return nil, 0, fmt.Errorf("%w: malformed Ed25519 key", errCOSE)
		}
		return ed25519.PublicKey(x), alg, nil
	case kty == ktyRSA && alg == COSEAlgRS256:
		n, e := coseBytes(m, coseRSAN, -1), coseBytes(m, coseRSAE, -1)
		if len(n) < 128 || len(e) == 0 || len(e) > 4 { // at least 1024 bits, the minimum crypto/rsa verifies
			return nil, 0, fmt.Errorf("%w: malformed RSA key", errCOSE)
		}
		exp := new(big.Int).SetBytes(e)
		if exp.Int64() < 3 || exp.Bit(0) == 0 {
			return nil, 0, fmt.Errorf("%w: invalid RSA exponent", errCOSE)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exp.Int64())}, alg, nil
	}
	return nil, 0, fmt.Errorf("%w: kty %d with alg %d", errCOSE, kty, alg)
}

// coseBytes returns a byte-string parameter of the given length, or of any
// length when size is negative; nil when absent or of a different shape.
func coseBytes(m cborMap, label int64, size int) []byte {
	b, ok := m[label].([]byte)
	if !ok || (size >= 0 && len(b) != size) {
		return nil
	}
	return b
}

func coseCurve(m cborMap, want int64) error {
	if crv, ok := m[int64(coseCrv)].(int64); !ok || crv != want {
		return errCOSE
	}
	return nil
}
