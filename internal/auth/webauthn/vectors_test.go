package webauthn

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"os"
	"strings"
	"testing"
)

type w3cVector struct {
	Section      string            `json:"section"`
	Name         string            `json:"name"`
	Registration map[string]string `json:"registration"`
	Auth         map[string]string `json:"authentication"`
}

func loadW3C(t *testing.T) []w3cVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/w3c-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []w3cVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) != 15 {
		t.Fatalf("%d vectors, want 15", len(file.Vectors))
	}
	return file.Vectors
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// credential builds the PublicKeyCredential JSON webauthn.js sends.
func credential(t testing.TB, id []byte, response map[string]any) jsontext.Value {
	t.Helper()
	enc := map[string]any{}
	for k, v := range response {
		if b, ok := v.([]byte); ok {
			enc[k] = encodeB64URL(b)
		} else {
			enc[k] = v
		}
	}
	raw, err := json.Marshal(map[string]any{
		"id": encodeB64URL(id), "rawId": encodeB64URL(id), "type": "public-key",
		"authenticatorAttachment": "platform", "clientExtensionResults": map[string]any{}, "response": enc,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

var w3cRP = RelyingParty{ID: "example.org", Name: "Example", Origin: "https://example.org"}

// TestW3CVectors runs the registration and authentication examples of
// WebAuthn Level 3, section 16. Registration verdicts: none and packed
// (self and x5c) with ES256, RS256 and EdDSA pass; ES384, ES512 and Ed448
// are not offered and fail; tpm, android-key, apple and fido-u2f are not
// supported formats; cross-origin ceremonies fail. The authentication
// examples are verified with the credential key of the registration, also
// where the attestation format is unsupported. The examples set UV at
// random, so they run without the UV requirement; with it, the verdicts
// follow the UV flag.
func TestW3CVectors(t *testing.T) {
	t.Parallel()
	type verdict struct{ reg, auth error }
	want := map[string]verdict{
		"none.ES256":                    {},
		"packed-self.ES256":             {},
		"none.ES256.crossOrigin":        {errClientData, errClientData},
		"none.ES256.topOrigin":          {errClientData, errClientData},
		"none.ES256.long-credential-id": {},
		"packed.ES256":                  {},
		"packed.ES384":                  {errCOSE, errCOSE},
		"packed.ES512":                  {errCOSE, errCOSE},
		"packed.RS256":                  {},
		"packed.EdDSA":                  {},
		"packed.Ed448":                  {errCOSE, errCOSE},
		"tpm.ES256":                     {errAttestation, nil},
		"android-key.ES256":             {errAttestation, nil},
		"apple.ES256":                   {errAttestation, nil},
		"fido-u2f.ES256":                {errAttestation, nil},
	}
	for _, v := range loadW3C(t) {
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()
			w, ok := want[v.Name]
			if !ok {
				t.Fatalf("no verdict for %s", v.Name)
			}
			r := v.Registration
			id := unhex(t, r["credential_id"])
			regCred := credential(t, id, map[string]any{
				"clientDataJSON": unhex(t, r["clientDataJSON"]), "attestationObject": unhex(t, r["attestationObject"]),
				"transports": []string{"internal"},
			})
			reg, err := w3cRP.verifyRegistration(regCred, unhex(t, r["challenge"]), false)
			if !errors.Is(err, w.reg) || (w.reg == nil) != (err == nil) {
				t.Fatalf("registration: %v, want %v", err, w.reg)
			}
			att, perr := parseAttestationObject(unhex(t, r["attestationObject"]))
			ad, aerr := parseAuthData(att.AuthData)
			if err == nil {
				if string(reg.CredentialID) != string(id) || reg.Alg != ad.Key.Alg || len(reg.Transports) != 1 {
					t.Fatalf("registration result %+v", reg)
				}
				uvErr := func() error { _, err := w3cRP.VerifyRegistration(regCred, unhex(t, r["challenge"])); return err }()
				if ad.Has(FlagUV) != (uvErr == nil) {
					t.Fatalf("UV policy: flags %#x, err %v", ad.Flags, uvErr)
				}
			}
			if perr != nil || aerr != nil {
				if w.auth == nil {
					t.Fatalf("credential key: %v %v", perr, aerr)
				}
				if !errors.Is(aerr, w.auth) {
					t.Fatalf("credential key: %v, want %v", aerr, w.auth)
				}
				return
			}
			a := v.Auth
			asn, err := ParseAssertion(credential(t, id, map[string]any{
				"clientDataJSON": unhex(t, a["clientDataJSON"]), "authenticatorData": unhex(t, a["authenticatorData"]),
				"signature": unhex(t, a["signature"]), "userHandle": nil,
			}))
			if err != nil {
				t.Fatal(err)
			}
			stored := Stored{Key: ad.Key, SignCount: ad.SignCount}
			res, err := w3cRP.verify(asn, stored, Expect{Challenge: unhex(t, a["challenge"])}, false)
			if !errors.Is(err, w.auth) || (w.auth == nil) != (err == nil) {
				t.Fatalf("authentication: %v, want %v", err, w.auth)
			}
			if err != nil {
				return
			}
			got, _ := parseAuthData(unhex(t, a["authenticatorData"]))
			_, uvErr := w3cRP.Verify(asn, stored, Expect{Challenge: unhex(t, a["challenge"])})
			if got.Has(FlagUV) != (uvErr == nil) || res.Flags != got.Flags {
				t.Fatalf("UV policy: flags %#x, err %v", got.Flags, uvErr)
			}
			// The same assertion must not pass for another RP, origin,
			// challenge or a tampered signature.
			negatives := map[string]func() error{
				"rp id": func() error {
					_, err := RelyingParty{ID: "example.com", Origin: w3cRP.Origin}.verify(asn, stored, Expect{Challenge: unhex(t, a["challenge"])}, false)
					return err
				},
				"origin": func() error {
					_, err := RelyingParty{ID: w3cRP.ID, Origin: "https://example.org:8443"}.verify(asn, stored, Expect{Challenge: unhex(t, a["challenge"])}, false)
					return err
				},
				"challenge": func() error {
					_, err := w3cRP.verify(asn, stored, Expect{Challenge: unhex(t, r["challenge"])}, false)
					return err
				},
				"signature": func() error {
					bad := asn
					bad.signature = append([]byte(nil), asn.signature...)
					bad.signature[len(bad.signature)/2] ^= 0x40
					_, err := w3cRP.verify(bad, stored, Expect{Challenge: unhex(t, a["challenge"])}, false)
					return err
				},
				"handle required": func() error {
					_, err := w3cRP.verify(asn, stored, Expect{Challenge: unhex(t, a["challenge"]), HandleRequired: true}, false)
					return err
				},
			}
			for name, f := range negatives {
				if f() == nil {
					t.Errorf("%s: accepted", name)
				}
			}
		})
	}
}

// TestW3CTamperedAttestation changes one byte of each signed part of the
// packed examples; every change must fail.
func TestW3CTamperedAttestation(t *testing.T) {
	t.Parallel()
	for _, v := range loadW3C(t) {
		if !strings.HasPrefix(v.Name, "packed") || v.Name == "packed.ES384" || v.Name == "packed.ES512" || v.Name == "packed.Ed448" {
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()
			r := v.Registration
			att, _ := parseAttestationObject(unhex(t, r["attestationObject"]))
			ad, err := parseAuthData(att.AuthData)
			if err != nil {
				t.Fatal(err)
			}
			cdHash := sha256Bytes(unhex(t, r["clientDataJSON"]))
			if err := verifyStatement(att, ad, cdHash); err != nil {
				t.Fatal(err)
			}
			sig := append([]byte(nil), att.Stmt["sig"].([]byte)...)
			sig[len(sig)-1] ^= 1
			bad := att
			bad.Stmt = cborMap{}
			for k, val := range att.Stmt {
				bad.Stmt[k] = val
			}
			bad.Stmt["sig"] = sig
			if verifyStatement(bad, ad, cdHash) == nil {
				t.Fatal("tampered signature accepted")
			}
			cdHash[0] ^= 1
			if verifyStatement(att, ad, cdHash) == nil {
				t.Fatal("other client data accepted")
			}
		})
	}
}

func sha256Bytes(b []byte) [32]byte { return sha256.Sum256(b) }
