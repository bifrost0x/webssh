package oidc

import (
	"crypto"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"os"
	"strings"
	"testing"
)

type rfcVector struct {
	JWK jsontext.Value `json:"jwk"`
	JWS string         `json:"jws"`
}

// TestRFCVectors verifies the examples of RFC 7515 A.2 (RS256), A.3
// (ES256) and RFC 8037 A.4 (EdDSA) and refuses every single-bit change.
func TestRFCVectors(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("testdata/rfc_jws_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors map[string]rfcVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 3 {
		t.Fatalf("%d vectors", len(vectors))
	}
	for name, v := range vectors {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			keys := mustKeys(t, jwks(string(v.JWK)))
			if _, _, err := verifyJWS(v.JWS, keys, allAlgs); err != nil {
				t.Fatalf("official vector refused: %v", err)
			}
			for i := range len(v.JWS) {
				if v.JWS[i] == '.' {
					continue
				}
				b := []byte(v.JWS)
				b[i] ^= 0x01
				if _, _, err := verifyJWS(string(b), keys, allAlgs); err == nil {
					t.Fatalf("token changed at %d accepted", i)
				}
			}
		})
	}
}

func TestEveryAlgorithmVerifies(t *testing.T) {
	t.Parallel()
	testKeys(t)
	set := jwks(rsaJWK(&rsaKeyA.PublicKey, "rsa", ""), ecJWK(ecKeys["P-256"], "p256", "P-256"),
		ecJWK(ecKeys["P-384"], "p384", "P-384"), ecJWK(ecKeys["P-521"], "p521", "P-521"), edJWK(edKey, "ed"))
	keys := mustKeys(t, set)
	for alg, kid := range map[string]string{"RS256": "rsa", "RS384": "rsa", "RS512": "rsa", "PS256": "rsa",
		"PS384": "rsa", "PS512": "rsa", "ES256": "p256", "ES384": "p384", "ES512": "p521", "EdDSA": "ed"} {
		signer := map[string]crypto.Signer{"rsa": rsaKeyA, "p256": ecKeys["P-256"], "p384": ecKeys["P-384"], "p521": ecKeys["P-521"], "ed": edKey}[kid]
		token := sign(t, alg, signer, `{"alg":"`+alg+`","kid":"`+kid+`"}`, `{"sub":"x"}`)
		if _, payload, err := verifyJWS(token, keys, allAlgs); err != nil || string(payload) != `{"sub":"x"}` {
			t.Fatalf("%s: %v", alg, err)
		}
	}
}

// TestKeyAlgorithmCurveBinding is the K7 condition: a token verifies only
// with the key its kid names, of the type and curve its alg requires, and
// within the JWK's own alg restriction.
func TestKeyAlgorithmCurveBinding(t *testing.T) {
	t.Parallel()
	testKeys(t)
	p256, p384 := ecKeys["P-256"], ecKeys["P-384"]
	cases := []struct {
		name  string
		set   []byte
		token string
		ok    bool
	}{
		{"kid selects key A", jwks(rsaJWK(&rsaKeyA.PublicKey, "a", ""), rsaJWK(&rsaKeyB.PublicKey, "b", "")),
			sign(t, "RS256", rsaKeyA, `{"alg":"RS256","kid":"a"}`, `{}`), true},
		{"kid of another key", jwks(rsaJWK(&rsaKeyA.PublicKey, "a", ""), rsaJWK(&rsaKeyB.PublicKey, "b", "")),
			sign(t, "RS256", rsaKeyA, `{"alg":"RS256","kid":"b"}`, `{}`), false},
		{"no kid, one key", jwks(rsaJWK(&rsaKeyA.PublicKey, "a", "")),
			sign(t, "RS256", rsaKeyA, `{"alg":"RS256"}`, `{}`), true},
		{"no kid, two candidate keys", jwks(rsaJWK(&rsaKeyA.PublicKey, "a", ""), rsaJWK(&rsaKeyB.PublicKey, "b", "")),
			sign(t, "RS256", rsaKeyA, `{"alg":"RS256"}`, `{}`), false},
		{"no kid, one key per type", jwks(rsaJWK(&rsaKeyA.PublicKey, "a", ""), ecJWK(p256, "e", "P-256")),
			sign(t, "ES256", p256, `{"alg":"ES256"}`, `{}`), true},
		{"duplicate kid", jwks(rsaJWK(&rsaKeyA.PublicKey, "a", ""), rsaJWK(&rsaKeyB.PublicKey, "a", "")),
			sign(t, "RS256", rsaKeyA, `{"alg":"RS256","kid":"a"}`, `{}`), false},
		{"JWK alg RS256 refuses PS256", jwks(rsaJWK(&rsaKeyA.PublicKey, "a", "RS256")),
			sign(t, "PS256", rsaKeyA, `{"alg":"PS256","kid":"a"}`, `{}`), false},
		{"JWK alg PS256 allows PS256", jwks(rsaJWK(&rsaKeyA.PublicKey, "a", "PS256")),
			sign(t, "PS256", rsaKeyA, `{"alg":"PS256","kid":"a"}`, `{}`), true},
		{"ES384 signature on a P-256 key", jwks(ecJWK(p256, "e", "P-256")),
			sign(t, "ES256", p256, `{"alg":"ES384","kid":"e"}`, `{}`), false},
		{"ES256 header with a P-384 key", jwks(ecJWK(p384, "e", "P-384")),
			sign(t, "ES384", p384, `{"alg":"ES256","kid":"e"}`, `{}`), false},
		{"RSA key for ES256", jwks(rsaJWK(&rsaKeyA.PublicKey, "a", "")),
			sign(t, "ES256", p256, `{"alg":"ES256","kid":"a"}`, `{}`), false},
		{"EC key for RS256", jwks(ecJWK(p256, "e", "P-256")),
			sign(t, "RS256", rsaKeyA, `{"alg":"RS256","kid":"e"}`, `{}`), false},
		{"Ed25519 key for ES256", jwks(edJWK(edKey, "d")),
			sign(t, "ES256", p256, `{"alg":"ES256","kid":"d"}`, `{}`), false},
		{"EC key for EdDSA", jwks(ecJWK(p256, "e", "P-256")),
			sign(t, "EdDSA", edKey, `{"alg":"EdDSA","kid":"e"}`, `{}`), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := verifyJWS(c.token, mustKeys(t, c.set), allAlgs)
			if c.ok && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !c.ok && !errors.Is(err, errSignature) {
				t.Fatalf("want errSignature, got %v", err)
			}
		})
	}
}

func TestHeaderAttacks(t *testing.T) {
	t.Parallel()
	testKeys(t)
	keys := mustKeys(t, jwks(rsaJWK(&rsaKeyA.PublicKey, "k1", "")))
	payload := b64([]byte(`{"sub":"x"}`))
	hs256 := func(header string) string {
		input := b64([]byte(header)) + "." + payload
		mac := hmac.New(sha256.New, []byte(rsaJWK(&rsaKeyA.PublicKey, "k1", "")))
		mac.Write([]byte(input))
		return input + "." + b64(mac.Sum(nil))
	}
	attacker := ecKeys["P-256"]
	valid := sign(t, "RS256", rsaKeyA, `{"alg":"RS256","kid":"k1"}`, `{"sub":"x"}`)
	cases := map[string]string{
		"alg none":            b64([]byte(`{"alg":"none"}`)) + "." + payload + ".",
		"alg None":            b64([]byte(`{"alg":"None"}`)) + "." + payload + ".",
		"alg missing":         b64([]byte(`{"kid":"k1"}`)) + "." + payload + ".",
		"alg not a string":    b64([]byte(`{"alg":7}`)) + "." + payload + ".",
		"HS256 with RSA key":  hs256(`{"alg":"HS256","kid":"k1"}`),
		"embedded jwk":        sign(t, "ES256", attacker, `{"alg":"ES256","jwk":`+ecJWK(attacker, "", "P-256")+`}`, `{"sub":"x"}`),
		"jku":                 sign(t, "ES256", attacker, `{"alg":"ES256","jku":"https://evil.example/jwks"}`, `{"sub":"x"}`),
		"crit":                sign(t, "RS256", rsaKeyA, `{"alg":"RS256","kid":"k1","crit":["exp"]}`, `{"sub":"x"}`),
		"duplicate alg":       sign(t, "RS256", rsaKeyA, `{"alg":"HS256","alg":"RS256","kid":"k1"}`, `{"sub":"x"}`),
		"unknown kid":         sign(t, "RS256", rsaKeyA, `{"alg":"RS256","kid":"other"}`, `{"sub":"x"}`),
		"four parts":          valid + ".x",
		"padded base64":       strings.Replace(valid, ".", "=.", 1),
		"JSON serialization":  `{"payload":"` + payload + `"}`,
		"header not JSON":     b64([]byte(`{`)) + "." + payload + ".AAAA",
		"oversized":           strings.Repeat("a", maxTokenBytes+1),
		"signature truncated": valid[:len(valid)-4],
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := verifyJWS(token, keys, allAlgs); !errors.Is(err, errSignature) {
				t.Fatalf("want errSignature, got %v", err)
			}
		})
	}
	t.Run("algorithm the provider does not announce", func(t *testing.T) {
		t.Parallel()
		if _, _, err := verifyJWS(valid, keys, map[string]bool{"ES256": true}); !errors.Is(err, errSignature) {
			t.Fatalf("want errSignature, got %v", err)
		}
	})
	t.Run("control", func(t *testing.T) {
		t.Parallel()
		if _, _, err := verifyJWS(valid, keys, allAlgs); err != nil {
			t.Fatal(err)
		}
	})
}

func TestParseJWKSRefusesUnsafeKeys(t *testing.T) {
	t.Parallel()
	testKeys(t)
	pub := b64(edKey.Public().(ed25519.PublicKey))
	ok := rsaJWK(&rsaKeyA.PublicKey, "a", "")
	smallN := `{"kty":"RSA","n":"` + b64(rsaKeyA.N.Bytes()[:128]) + `","e":"AQAB"}`
	for name, set := range map[string]string{
		"symmetric":            `{"keys":[{"kty":"oct","k":"c2VjcmV0"}]}`,
		"rsa 1024":             `{"keys":[` + smallN + `]}`,
		"rsa even exponent":    `{"keys":[{"kty":"RSA","n":"` + b64(rsaKeyA.N.Bytes()) + `","e":"Ag"}]}`,
		"private material":     `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + pub + `","d":"` + pub + `"}]}`,
		"encryption key":       `{"keys":[{"kty":"OKP","crv":"Ed25519","use":"enc","x":"` + pub + `"}]}`,
		"no verify in key_ops": `{"keys":[{"kty":"OKP","crv":"Ed25519","key_ops":["sign"],"x":"` + pub + `"}]}`,
		"point off curve":      `{"keys":[{"kty":"EC","crv":"P-256","x":"` + b64(make([]byte, 32)) + `","y":"` + b64(make([]byte, 32)) + `"}]}`,
		"short coordinate":     `{"keys":[{"kty":"EC","crv":"P-256","x":"AAAA","y":"AAAA"}]}`,
		"alg and curve differ": `{"keys":[` + strings.Replace(ecJWK(ecKeys["P-256"], "e", "P-256"), `"kty"`, `"alg":"ES384","kty"`, 1) + `]}`,
		"unsupported alg":      `{"keys":[` + rsaJWK(&rsaKeyA.PublicKey, "a", "HS256") + `]}`,
		"X25519":               `{"keys":[{"kty":"OKP","crv":"X25519","x":"` + pub + `"}]}`,
		"empty":                `{"keys":[]}`,
		"too many keys":        `{"keys":[` + strings.TrimSuffix(strings.Repeat(ok+",", maxKeys+1), ",") + `]}`,
		"not JSON":             `[`,
		"duplicate member":     `{"keys":[],"keys":[` + ok + `]}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseJWKS([]byte(set)); err == nil {
				t.Fatal("unsafe key set accepted")
			}
		})
	}
	t.Run("unusable keys beside a good one are skipped", func(t *testing.T) {
		t.Parallel()
		keys := mustKeys(t, []byte(`{"keys":[{"kty":"oct","k":"c2VjcmV0"},`+ok+`]}`))
		if len(keys) != 1 || keys[0].kid != "a" {
			t.Fatalf("keys %+v", keys)
		}
	})
}

func FuzzVerifyJWS(f *testing.F) {
	f.Add("eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.AAAA")
	f.Add("a.b.c")
	f.Add("eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIn0.e30.")
	testKeys(f)
	keys := mustKeys(f, jwks(rsaJWK(&rsaKeyA.PublicKey, "k1", ""), edJWK(edKey, "ed"), ecJWK(ecKeys["P-256"], "e", "P-256")))
	f.Fuzz(func(t *testing.T, token string) {
		if _, _, err := verifyJWS(token, keys, allAlgs); err == nil {
			t.Fatalf("forged token accepted: %q", token)
		}
	})
}

func FuzzParseJWKS(f *testing.F) {
	testKeys(f)
	f.Add(jwks(rsaJWK(&rsaKeyA.PublicKey, "k1", "")))
	f.Add(jwks(ecJWK(ecKeys["P-384"], "e", "P-384"), edJWK(edKey, "d")))
	f.Add([]byte(`{"keys":[{"kty":"EC","crv":"P-521","x":"","y":""}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		keys, err := parseJWKS(data)
		if err != nil {
			return
		}
		if len(keys) == 0 || len(keys) > maxKeys {
			t.Fatalf("%d keys", len(keys))
		}
		for _, k := range keys {
			if k.key == nil {
				t.Fatal("nil key")
			}
		}
	})
}
