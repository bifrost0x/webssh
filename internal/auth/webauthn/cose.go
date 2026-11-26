package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

// COSE algorithms WebAuthn accepts: the default list of the Python release
// (py_webauthn), in the order its registration options offer them.
const (
	AlgEdDSA int64 = -8
	AlgES256 int64 = -7
	AlgRS256 int64 = -257
)

// algorithms is the pubKeyCredParams list of the registration options.
func algorithms() []int64 { return []int64{AlgEdDSA, AlgES256, AlgRS256} }

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

// RSA moduli outside this range are refused; crypto/rsa does not verify
// below 1024 bits.
const (
	rsaMinBits = 1024
	rsaMaxBits = 8192
)

var (
	errCOSE      = errors.New("webauthn: unsupported COSE key")
	errSignature = errors.New("webauthn: signature does not verify")
)

// PublicKey is a parsed credential public key.
type PublicKey struct {
	Alg int64
	key crypto.PublicKey // *ecdsa.PublicKey, *rsa.PublicKey or ed25519.PublicKey
}

// ParseCOSEKey parses a COSE_Key of one of the three supported algorithms
// and checks that key type, curve and algorithm agree. Parameters other
// than those of the key type are ignored.
func ParseCOSEKey(data []byte) (PublicKey, error) {
	v, err := decodeCBOR(data)
	if err != nil {
		return PublicKey{}, err
	}
	return coseKeyFrom(v)
}

func coseKeyFrom(v any) (PublicKey, error) {
	m, ok := v.(cborMap)
	if !ok {
		return PublicKey{}, fmt.Errorf("%w: not a map", errCOSE)
	}
	kty, okKty := m[int64(coseKty)].(int64)
	alg, okAlg := m[int64(coseAlg)].(int64)
	if !okKty || !okAlg {
		return PublicKey{}, fmt.Errorf("%w: missing kty or alg", errCOSE)
	}
	switch {
	case kty == ktyEC2 && alg == AlgES256:
		x, y := coseBytes(m, coseX, 32), coseBytes(m, coseY, 32)
		if x == nil || y == nil || !coseCurve(m, crvP256) {
			return PublicKey{}, fmt.Errorf("%w: malformed P-256 key", errCOSE)
		}
		point := make([]byte, 0, 65)
		point = append(append(append(point, 4), x...), y...)
		key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
		if err != nil {
			return PublicKey{}, fmt.Errorf("%w: %w", errCOSE, err)
		}
		return PublicKey{Alg: alg, key: key}, nil
	case kty == ktyOKP && alg == AlgEdDSA:
		x := coseBytes(m, coseX, ed25519.PublicKeySize)
		if x == nil || !coseCurve(m, crvEd25519) {
			return PublicKey{}, fmt.Errorf("%w: malformed Ed25519 key", errCOSE)
		}
		return PublicKey{Alg: alg, key: ed25519.PublicKey(append([]byte(nil), x...))}, nil
	case kty == ktyRSA && alg == AlgRS256:
		n, e := coseBytes(m, coseRSAN, -1), coseBytes(m, coseRSAE, -1)
		if n == nil || len(e) == 0 || len(e) > 4 {
			return PublicKey{}, fmt.Errorf("%w: malformed RSA key", errCOSE)
		}
		mod := new(big.Int).SetBytes(n)
		if mod.BitLen() < rsaMinBits || mod.BitLen() > rsaMaxBits || mod.Bit(0) == 0 {
			return PublicKey{}, fmt.Errorf("%w: RSA modulus of %d bits", errCOSE, mod.BitLen())
		}
		exp := new(big.Int).SetBytes(e).Int64()
		if exp < 3 || exp > 1<<31-1 || exp%2 == 0 {
			return PublicKey{}, fmt.Errorf("%w: invalid RSA exponent", errCOSE)
		}
		return PublicKey{Alg: alg, key: &rsa.PublicKey{N: mod, E: int(exp)}}, nil
	}
	return PublicKey{}, fmt.Errorf("%w: kty %d with alg %d", errCOSE, kty, alg)
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

func coseCurve(m cborMap, want int64) bool {
	crv, ok := m[int64(coseCrv)].(int64)
	return ok && crv == want
}

// Verify checks sig over signed with the key's algorithm: ES256 takes an
// ASN.1 DER signature, RS256 PKCS #1 v1.5, EdDSA pure Ed25519.
func (k PublicKey) Verify(signed, sig []byte) error {
	return verifySignature(k.Alg, k.key, signed, sig)
}

// verifySignature checks sig over signed for a key of algorithm alg; the
// key type must match the algorithm.
func verifySignature(alg int64, key crypto.PublicKey, signed, sig []byte) error {
	ok := false
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		if alg == AlgES256 && k.Curve == elliptic.P256() {
			digest := sha256.Sum256(signed)
			ok = ecdsa.VerifyASN1(k, digest[:], sig)
		}
	case *rsa.PublicKey:
		if alg == AlgRS256 {
			digest := sha256.Sum256(signed)
			ok = rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig) == nil
		}
	case ed25519.PublicKey:
		if alg == AlgEdDSA && len(k) == ed25519.PublicKeySize {
			ok = ed25519.Verify(k, signed, sig)
		}
	}
	if !ok {
		return errSignature
	}
	return nil
}
