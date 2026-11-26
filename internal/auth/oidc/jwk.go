package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"math/big"
	"slices"
)

// Bounds of a JWK Set. RSA keys below 2048 bits are refused (NIST SP
// 800-57); keys above 8192 bits only cost verification time.
const (
	minRSABits = 2048
	maxRSABits = 8192
	maxKeys    = 64
)

// jwk is one parsed verification key (RFC 7517, RFC 7518 section 6,
// RFC 8037). Keys that cannot verify signatures are dropped on parse.
type jwk struct {
	kid string
	alg string // the JWK's own alg member restricts the key to it
	crv string // EC and OKP keys
	key crypto.PublicKey
}

type rawJWK struct {
	Kty    string   `json:"kty"`
	Use    string   `json:"use"`
	KeyOps []string `json:"key_ops"`
	Alg    string   `json:"alg"`
	Kid    string   `json:"kid"`
	N      string   `json:"n"`
	E      string   `json:"e"`
	Crv    string   `json:"crv"`
	X      string   `json:"x"`
	Y      string   `json:"y"`
	D      string   `json:"d"`
	K      string   `json:"k"`
}

// parseJWKS decodes a JWK Set and keeps the public signature keys of the
// supported types. A key with private or symmetric material, another use,
// or an unknown type is skipped; a set without any usable key is an error.
func parseJWKS(data []byte) ([]jwk, error) {
	var set struct {
		Keys []jsontext.Value `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("oidc: jwks: %w", err)
	}
	if len(set.Keys) > maxKeys {
		return nil, errors.New("oidc: jwks has too many keys")
	}
	var out []jwk
	for _, raw := range set.Keys {
		var k rawJWK
		if err := json.Unmarshal(raw, &k); err != nil {
			continue
		}
		key, err := k.publicKey()
		if err != nil {
			continue
		}
		out = append(out, jwk{kid: k.Kid, alg: k.Alg, crv: k.Crv, key: key})
	}
	if len(out) == 0 {
		return nil, errors.New("oidc: jwks has no usable signature key")
	}
	return out, nil
}

func (k rawJWK) publicKey() (crypto.PublicKey, error) {
	if k.D != "" || k.K != "" {
		return nil, errors.New("private or symmetric key material")
	}
	if k.Use != "" && k.Use != "sig" {
		return nil, errors.New("key not for signatures")
	}
	if len(k.KeyOps) > 0 && !slices.Contains(k.KeyOps, "verify") {
		return nil, errors.New("key not for verification")
	}
	if a, ok := algorithms[k.Alg]; k.Alg != "" && !ok {
		return nil, errors.New("key restricted to an unsupported algorithm")
	} else if ok && a.curve != "" && a.curve != k.Crv {
		return nil, errors.New("key algorithm and curve disagree")
	}
	switch k.Kty {
	case "RSA":
		return rsaKey(k.N, k.E)
	case "EC":
		curve, size := curveFor(k.Crv)
		if curve == nil {
			return nil, errors.New("unsupported curve")
		}
		x, err := b64Fixed(k.X, size)
		if err != nil {
			return nil, err
		}
		y, err := b64Fixed(k.Y, size)
		if err != nil {
			return nil, err
		}
		// ParseUncompressedPublicKey refuses points that are not on the
		// curve (invalid-curve attacks).
		return ecdsa.ParseUncompressedPublicKey(curve, append(append([]byte{4}, x...), y...))
	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, errors.New("unsupported OKP curve")
		}
		x, err := b64Fixed(k.X, ed25519.PublicKeySize)
		if err != nil {
			return nil, err
		}
		return ed25519.PublicKey(x), nil
	}
	return nil, errors.New("unsupported key type")
}

func rsaKey(n64, e64 string) (*rsa.PublicKey, error) {
	n, err := b64Int(n64)
	if err != nil {
		return nil, err
	}
	e, err := b64Int(e64)
	if err != nil || !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 || e.Bit(0) == 0 {
		return nil, errors.New("invalid RSA exponent")
	}
	if bits := n.BitLen(); bits < minRSABits || bits > maxRSABits {
		return nil, errors.New("RSA modulus size not accepted")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

func curveFor(crv string) (elliptic.Curve, int) {
	switch crv {
	case "P-256":
		return elliptic.P256(), 32
	case "P-384":
		return elliptic.P384(), 48
	case "P-521":
		return elliptic.P521(), 66
	}
	return nil, 0
}

// b64Int decodes an unsigned big-endian integer (RFC 7518 section 2,
// Base64urlUInt) without padding. A leading zero octet, which some
// providers emit, is accepted as the Python release accepts it.
func b64Int(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) == 0 || len(b) > maxRSABits/8+1 {
		return nil, errors.New("invalid base64url integer")
	}
	return new(big.Int).SetBytes(b), nil
}

func b64Fixed(s string, size int) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != size {
		return nil, errors.New("invalid base64url coordinate")
	}
	return b, nil
}
