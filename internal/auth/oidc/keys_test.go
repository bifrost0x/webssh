package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"sync"
	"testing"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

var allAlgs = map[string]bool{"RS256": true, "RS384": true, "RS512": true, "PS256": true, "PS384": true,
	"PS512": true, "ES256": true, "ES384": true, "ES512": true, "EdDSA": true}

// Generated keys are shared between tests: RSA generation is slow under
// the race detector.
var (
	keyOnce  sync.Once
	rsaKeyA  *rsa.PrivateKey
	rsaKeyB  *rsa.PrivateKey
	ecKeys   map[string]*ecdsa.PrivateKey
	edKey    ed25519.PrivateKey
	keyError error
)

func testKeys(t testing.TB) {
	t.Helper()
	keyOnce.Do(func() {
		var err error
		if rsaKeyA, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			keyError = err
			return
		}
		if rsaKeyB, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			keyError = err
			return
		}
		ecKeys = map[string]*ecdsa.PrivateKey{}
		for name, c := range map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()} {
			if ecKeys[name], err = ecdsa.GenerateKey(c, rand.Reader); err != nil {
				keyError = err
				return
			}
		}
		_, edKey, keyError = ed25519.GenerateKey(rand.Reader)
	})
	if keyError != nil {
		t.Fatal(keyError)
	}
}

func rsaJWK(pub *rsa.PublicKey, kid, alg string) string {
	e := big.NewInt(int64(pub.E)).Bytes()
	s := `{"kty":"RSA","kid":"` + kid + `","n":"` + b64(pub.N.Bytes()) + `","e":"` + b64(e) + `"`
	if alg != "" {
		s += `,"alg":"` + alg + `"`
	}
	return s + "}"
}

func ecJWK(k *ecdsa.PrivateKey, kid, crv string) string {
	size := (k.Curve.Params().BitSize + 7) / 8
	raw, _ := k.PublicKey.Bytes() // uncompressed point: 0x04 || X || Y
	return `{"kty":"EC","kid":"` + kid + `","crv":"` + crv + `","x":"` + b64(raw[1:1+size]) + `","y":"` + b64(raw[1+size:]) + `"}`
}

func edJWK(k ed25519.PrivateKey, kid string) string {
	return `{"kty":"OKP","kid":"` + kid + `","crv":"Ed25519","x":"` + b64(k.Public().(ed25519.PublicKey)) + `"}`
}

func jwks(keys ...string) []byte {
	out := `{"keys":[`
	for i, k := range keys {
		if i > 0 {
			out += ","
		}
		out += k
	}
	return []byte(out + "]}")
}

// sign signs header and payload with key for alg; it signs what it is
// told, so tests can build mismatched tokens.
func sign(t testing.TB, alg string, key crypto.Signer, header, payload string) string {
	t.Helper()
	input := b64([]byte(header)) + "." + b64([]byte(payload))
	a, ok := algorithms[alg]
	if !ok {
		t.Fatalf("unknown alg %s", alg)
	}
	var sig []byte
	var err error
	switch k := key.(type) {
	case *rsa.PrivateKey:
		h := a.hash.New()
		h.Write([]byte(input))
		if a.family == familyPSS {
			sig, err = rsa.SignPSS(rand.Reader, k, a.hash, h.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		} else {
			sig, err = rsa.SignPKCS1v15(rand.Reader, k, a.hash, h.Sum(nil))
		}
	case *ecdsa.PrivateKey:
		h := a.hash.New()
		h.Write([]byte(input))
		var r, s *big.Int
		r, s, err = ecdsa.Sign(rand.Reader, k, h.Sum(nil))
		size := (k.Curve.Params().BitSize + 7) / 8
		if err == nil {
			sig = append(r.FillBytes(make([]byte, size)), s.FillBytes(make([]byte, size))...)
		}
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, []byte(input))
	default:
		t.Fatalf("unsupported key %T", key)
	}
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64(sig)
}

func mustKeys(t testing.TB, set []byte) []jwk {
	t.Helper()
	keys, err := parseJWKS(set)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}
