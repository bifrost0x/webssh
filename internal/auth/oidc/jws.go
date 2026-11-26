package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	_ "crypto/sha256" // registers SHA-256 for crypto.Hash
	_ "crypto/sha512" // registers SHA-384 and SHA-512
	"encoding/base64"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// errSignature is every refusal of an ID Token signature or header. The
// detail is for the log; the user sees auth_failed only.
var errSignature = errors.New("oidc: id token signature invalid")

// errNoKey means that no key of the JWKS is bound to the token's kid and
// algorithm; the provider may have rotated its keys.
var errNoKey = fmt.Errorf("%w: no key bound to the header", errSignature)

// maxTokenBytes bounds a compact ID Token before any decoding.
const maxTokenBytes = 64 << 10

// family is the key type an algorithm needs.
type family int

const (
	familyRSA family = iota + 1
	familyPSS
	familyEC
	familyEdDSA
)

// algorithm is one accepted JWS algorithm (RFC 7518 section 3, RFC 8037).
// curve binds the ECDSA algorithms to their curve (RFC 7518 section 3.4).
type algorithm struct {
	hash   crypto.Hash
	family family
	curve  string
}

// algorithms are the only signatures ever accepted. Symmetric (HS*) and
// "none" are absent on purpose: with HS256 an attacker who knows the
// public key could sign tokens (algorithm confusion).
var algorithms = map[string]algorithm{
	"RS256": {crypto.SHA256, familyRSA, ""}, "RS384": {crypto.SHA384, familyRSA, ""}, "RS512": {crypto.SHA512, familyRSA, ""},
	"PS256": {crypto.SHA256, familyPSS, ""}, "PS384": {crypto.SHA384, familyPSS, ""}, "PS512": {crypto.SHA512, familyPSS, ""},
	"ES256": {crypto.SHA256, familyEC, "P-256"}, "ES384": {crypto.SHA384, familyEC, "P-384"}, "ES512": {crypto.SHA512, familyEC, "P-521"},
	"EdDSA": {0, familyEdDSA, "Ed25519"},
}

// header is the protected JOSE header. Keys carried or referenced by the
// header itself (jwk, jku, x5u, x5c) are never used: only the provider's
// JWKS counts.
type header struct {
	Alg  string         `json:"alg"`
	Kid  string         `json:"kid"`
	Crit jsontext.Value `json:"crit"`
}

// verifyJWS checks a compact JWS against keys and returns its header and
// payload. allowed is the set of algorithms the provider announced. The
// key is bound to the token in three ways: its kid (a header without kid
// needs a JWKS with exactly one key for the algorithm), its type and curve
// (RSA for RS/PS, the curve of the ES algorithm, Ed25519 for EdDSA) and
// the JWK's own alg member when it has one.
func verifyJWS(token string, keys []jwk, allowed map[string]bool) (header, []byte, error) {
	var hdr header
	if len(token) > maxTokenBytes {
		return hdr, nil, fmt.Errorf("%w: token too large", errSignature)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return hdr, nil, fmt.Errorf("%w: not a compact JWS", errSignature)
	}
	dec := base64.RawURLEncoding.Strict()
	rawHeader, err1 := dec.DecodeString(parts[0])
	payload, err2 := dec.DecodeString(parts[1])
	sig, err3 := dec.DecodeString(parts[2])
	if err := errors.Join(err1, err2, err3); err != nil {
		return hdr, nil, fmt.Errorf("%w: base64url: %w", errSignature, err)
	}
	// encoding/json/v2 refuses duplicate member names, so a second "alg"
	// cannot override the first.
	if err := json.Unmarshal(rawHeader, &hdr); err != nil {
		return hdr, nil, fmt.Errorf("%w: header: %w", errSignature, err)
	}
	alg, ok := algorithms[hdr.Alg]
	if !ok || !allowed[hdr.Alg] {
		return hdr, nil, fmt.Errorf("%w: algorithm %q not accepted", errSignature, hdr.Alg)
	}
	if len(hdr.Crit) > 0 {
		return hdr, nil, fmt.Errorf("%w: critical header parameters are not supported", errSignature)
	}
	key, err := bindKey(keys, hdr, alg)
	if err != nil {
		return hdr, nil, err
	}
	input := []byte(token[:len(parts[0])+1+len(parts[1])])
	if !verifyWith(key.key, alg, input, sig) {
		return hdr, nil, fmt.Errorf("%w: signature does not verify", errSignature)
	}
	return hdr, payload, nil
}

// bindKey selects the one key of keys that may verify a token with hdr.
// A kid that names two usable keys is ambiguous and refused.
func bindKey(keys []jwk, hdr header, alg algorithm) (jwk, error) {
	var match []jwk
	for _, k := range keys {
		if hdr.Kid != "" && k.kid != hdr.Kid {
			continue
		}
		if k.alg != "" && k.alg != hdr.Alg {
			continue
		}
		if !k.fits(alg) {
			continue
		}
		match = append(match, k)
	}
	switch {
	case len(match) == 1:
		return match[0], nil
	case len(match) == 0:
		return jwk{}, errNoKey
	default:
		return jwk{}, fmt.Errorf("%w: %d keys match the header", errSignature, len(match))
	}
}

// fits reports whether the key's type and curve belong to alg.
func (k jwk) fits(alg algorithm) bool {
	switch pub := k.key.(type) {
	case *rsa.PublicKey:
		return alg.family == familyRSA || alg.family == familyPSS
	case *ecdsa.PublicKey:
		return alg.family == familyEC && k.crv == alg.curve && pub.Curve.Params().Name == alg.curve
	case ed25519.PublicKey:
		return alg.family == familyEdDSA && k.crv == alg.curve
	}
	return false
}

func verifyWith(key crypto.PublicKey, alg algorithm, input, sig []byte) bool {
	var digest []byte
	if alg.hash != 0 {
		h := alg.hash.New()
		h.Write(input)
		digest = h.Sum(nil)
	}
	switch pub := key.(type) {
	case *rsa.PublicKey:
		switch alg.family {
		case familyRSA:
			return rsa.VerifyPKCS1v15(pub, alg.hash, digest, sig) == nil
		case familyPSS:
			opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: alg.hash}
			return rsa.VerifyPSS(pub, alg.hash, digest, sig, opts) == nil
		}
	case *ecdsa.PublicKey:
		// JWS carries R and S as fixed-size big-endian halves (RFC 7518
		// section 3.4), not ASN.1.
		size := (pub.Curve.Params().BitSize + 7) / 8
		if alg.family != familyEC || len(sig) != 2*size {
			return false
		}
		r := new(big.Int).SetBytes(sig[:size])
		s := new(big.Int).SetBytes(sig[size:])
		return ecdsa.Verify(pub, digest, r, s)
	case ed25519.PublicKey:
		return alg.family == familyEdDSA && ed25519.Verify(pub, input, sig)
	}
	return false
}
