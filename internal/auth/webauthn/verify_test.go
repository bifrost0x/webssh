package webauthn

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
)

var testRP = RelyingParty{ID: "localhost", Name: "WebSSH", Origin: "http://localhost:4173"}

func challenge32() []byte { return bytes.Repeat([]byte{7}, 32) }

func TestRegistrationFormatsAndAlgorithms(t *testing.T) {
	t.Parallel()
	for _, alg := range []int64{AlgES256, AlgEdDSA, AlgRS256} {
		for _, kind := range []int{attNone, attSelf, attX5C} {
			a := newAuthenticator(t, testRP, alg, "7")
			reg, err := testRP.VerifyRegistration(a.register(t, challenge32(), kind), challenge32())
			if err != nil {
				t.Fatalf("alg %d kind %d: %v", alg, kind, err)
			}
			if reg.Alg != alg || !bytes.Equal(reg.CredentialID, a.id) || len(reg.Transports) != 2 {
				t.Fatalf("result %+v", reg)
			}
			key, err := ParseCOSEKey(reg.COSEKey)
			if err != nil || key.Alg != alg {
				t.Fatalf("stored key: %v", err)
			}
			res, err := testRP.Verify(mustParse(t, a.assert(t, challenge32(), assertOpts{})), Stored{Key: key, UserHandle: "7"}, Expect{Challenge: challenge32(), HandleRequired: true})
			if err != nil || res.SignCount != 0 {
				t.Fatalf("assertion after registration: %+v %v", res, err)
			}
		}
	}
}

func mustParse(t *testing.T, raw jsontext.Value) Assertion {
	t.Helper()
	a, err := ParseAssertion(raw)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// TestRegistrationRefusals covers every registration check with one
// changed input.
func TestRegistrationRefusals(t *testing.T) {
	t.Parallel()
	ch := challenge32()
	cases := map[string]func(t *testing.T) (jsontext.Value, RelyingParty){
		"wrong challenge": func(t *testing.T) (jsontext.Value, RelyingParty) {
			return newAuthenticator(t, testRP, AlgES256, "7").register(t, []byte("another challenge 0123456789abcdef"), attNone), testRP
		},
		"wrong origin": func(t *testing.T) (jsontext.Value, RelyingParty) {
			return newAuthenticator(t, testRP, AlgES256, "7").register(t, ch, attNone), RelyingParty{ID: testRP.ID, Origin: "https://localhost"}
		},
		"wrong rp id": func(t *testing.T) (jsontext.Value, RelyingParty) {
			return newAuthenticator(t, testRP, AlgES256, "7").register(t, ch, attNone), RelyingParty{ID: "LOCALHOST", Origin: testRP.Origin}
		},
		"no user verification": func(t *testing.T) (jsontext.Value, RelyingParty) {
			a := newAuthenticator(t, testRP, AlgES256, "7")
			a.flags = FlagUP
			return a.register(t, ch, attNone), testRP
		},
		"no user presence": func(t *testing.T) (jsontext.Value, RelyingParty) {
			a := newAuthenticator(t, testRP, AlgES256, "7")
			a.flags = FlagUV
			return a.register(t, ch, attNone), testRP
		},
		"backed up but not eligible": func(t *testing.T) (jsontext.Value, RelyingParty) {
			a := newAuthenticator(t, testRP, AlgES256, "7")
			a.flags = FlagUP | FlagUV | FlagBS
			return a.register(t, ch, attNone), testRP
		},
		"get instead of create": func(t *testing.T) (jsontext.Value, RelyingParty) {
			a := newAuthenticator(t, testRP, AlgES256, "7")
			cdj := clientDataJSON(t, typeGet, ch, testRP.Origin, nil)
			return credential(t, a.id, map[string]any{"clientDataJSON": cdj, "attestationObject": a.attestationObject(t, a.authData(a.flags, 0, true), cdj, attNone)}), testRP
		},
		"no attested credential": func(t *testing.T) (jsontext.Value, RelyingParty) {
			a := newAuthenticator(t, testRP, AlgES256, "7")
			cdj := clientDataJSON(t, typeCreate, ch, testRP.Origin, nil)
			return credential(t, a.id, map[string]any{"clientDataJSON": cdj, "attestationObject": a.attestationObject(t, a.authData(a.flags, 0, false), cdj, attNone)}), testRP
		},
		"rawId differs from attested id": func(t *testing.T) (jsontext.Value, RelyingParty) {
			a := newAuthenticator(t, testRP, AlgES256, "7")
			cdj := clientDataJSON(t, typeCreate, ch, testRP.Origin, nil)
			return credential(t, []byte("another-credential-id"), map[string]any{"clientDataJSON": cdj, "attestationObject": a.attestationObject(t, a.authData(a.flags, 0, true), cdj, attNone)}), testRP
		},
		"unsupported format": func(t *testing.T) (jsontext.Value, RelyingParty) {
			a := newAuthenticator(t, testRP, AlgES256, "7")
			cdj := clientDataJSON(t, typeCreate, ch, testRP.Origin, nil)
			ao := cborEncode([]cborPair{{"fmt", "fido-u2f"}, {"attStmt", []cborPair{}}, {"authData", a.authData(a.flags, 0, true)}})
			return credential(t, a.id, map[string]any{"clientDataJSON": cdj, "attestationObject": ao}), testRP
		},
		"none with statement": func(t *testing.T) (jsontext.Value, RelyingParty) {
			a := newAuthenticator(t, testRP, AlgES256, "7")
			cdj := clientDataJSON(t, typeCreate, ch, testRP.Origin, nil)
			ao := cborEncode([]cborPair{{"fmt", "none"}, {"attStmt", []cborPair{{"alg", -7}}}, {"authData", a.authData(a.flags, 0, true)}})
			return credential(t, a.id, map[string]any{"clientDataJSON": cdj, "attestationObject": ao}), testRP
		},
		"self attestation with another alg": func(t *testing.T) (jsontext.Value, RelyingParty) {
			a := newAuthenticator(t, testRP, AlgES256, "7")
			cdj := clientDataJSON(t, typeCreate, ch, testRP.Origin, nil)
			ad := a.authData(a.flags, 0, true)
			h := sha256Bytes(cdj)
			ao := cborEncode([]cborPair{{"fmt", "packed"}, {"attStmt", []cborPair{{"alg", AlgRS256}, {"sig", a.key.sign(t, append(append([]byte(nil), ad...), h[:]...))}}}, {"authData", ad}})
			return credential(t, a.id, map[string]any{"clientDataJSON": cdj, "attestationObject": ao}), testRP
		},
		"x5c with CA certificate": func(t *testing.T) (jsontext.Value, RelyingParty) {
			a := newAuthenticator(t, testRP, AlgES256, "7")
			cdj := clientDataJSON(t, typeCreate, ch, testRP.Origin, nil)
			ad := a.authData(a.flags, 0, true)
			h := sha256Bytes(cdj)
			ak := newSoftKey(t, AlgES256)
			stmt := []cborPair{{"alg", AlgES256}, {"sig", ak.sign(t, append(append([]byte(nil), ad...), h[:]...))}, {"x5c", []any{attestationCert(t, ak, a.aaguid, true)}}}
			return credential(t, a.id, map[string]any{"clientDataJSON": cdj, "attestationObject": cborEncode([]cborPair{{"fmt", "packed"}, {"attStmt", stmt}, {"authData", ad}})}), testRP
		},
		"x5c with another AAGUID": func(t *testing.T) (jsontext.Value, RelyingParty) {
			a := newAuthenticator(t, testRP, AlgES256, "7")
			cdj := clientDataJSON(t, typeCreate, ch, testRP.Origin, nil)
			ad := a.authData(a.flags, 0, true)
			h := sha256Bytes(cdj)
			ak := newSoftKey(t, AlgES256)
			other := a.aaguid
			other[3] ^= 1
			stmt := []cborPair{{"alg", AlgES256}, {"sig", ak.sign(t, append(append([]byte(nil), ad...), h[:]...))}, {"x5c", []any{attestationCert(t, ak, other, false)}}}
			return credential(t, a.id, map[string]any{"clientDataJSON": cdj, "attestationObject": cborEncode([]cborPair{{"fmt", "packed"}, {"attStmt", stmt}, {"authData", ad}})}), testRP
		},
		"x5c signature by another key": func(t *testing.T) (jsontext.Value, RelyingParty) {
			a := newAuthenticator(t, testRP, AlgES256, "7")
			cdj := clientDataJSON(t, typeCreate, ch, testRP.Origin, nil)
			ad := a.authData(a.flags, 0, true)
			h := sha256Bytes(cdj)
			stmt := []cborPair{{"alg", AlgES256}, {"sig", a.key.sign(t, append(append([]byte(nil), ad...), h[:]...))}, {"x5c", []any{attestationCert(t, newSoftKey(t, AlgES256), a.aaguid, false)}}}
			return credential(t, a.id, map[string]any{"clientDataJSON": cdj, "attestationObject": cborEncode([]cborPair{{"fmt", "packed"}, {"attStmt", stmt}, {"authData", ad}})}), testRP
		},
		"trailing bytes after attestation object": func(t *testing.T) (jsontext.Value, RelyingParty) {
			a := newAuthenticator(t, testRP, AlgES256, "7")
			cdj := clientDataJSON(t, typeCreate, ch, testRP.Origin, nil)
			ao := append(a.attestationObject(t, a.authData(a.flags, 0, true), cdj, attNone), 0)
			return credential(t, a.id, map[string]any{"clientDataJSON": cdj, "attestationObject": ao}), testRP
		},
		"trailing bytes in authenticator data": func(t *testing.T) (jsontext.Value, RelyingParty) {
			a := newAuthenticator(t, testRP, AlgES256, "7")
			cdj := clientDataJSON(t, typeCreate, ch, testRP.Origin, nil)
			ad := append(a.authData(a.flags, 0, true), 0xa0)
			return credential(t, a.id, map[string]any{"clientDataJSON": cdj, "attestationObject": a.attestationObject(t, ad, cdj, attNone)}), testRP
		},
		"cross origin": func(t *testing.T) (jsontext.Value, RelyingParty) {
			a := newAuthenticator(t, testRP, AlgES256, "7")
			cdj := clientDataJSON(t, typeCreate, ch, testRP.Origin, map[string]any{"crossOrigin": true})
			return credential(t, a.id, map[string]any{"clientDataJSON": cdj, "attestationObject": a.attestationObject(t, a.authData(a.flags, 0, true), cdj, attNone)}), testRP
		},
		"wrong credential type": func(t *testing.T) (jsontext.Value, RelyingParty) {
			raw := newAuthenticator(t, testRP, AlgES256, "7").register(t, ch, attNone)
			return jsontext.Value(strings.Replace(string(raw), `"public-key"`, `"password"`, 1)), testRP
		},
		"id differs from rawId": func(t *testing.T) (jsontext.Value, RelyingParty) {
			raw := newAuthenticator(t, testRP, AlgES256, "7").register(t, ch, attNone)
			return jsontext.Value(strings.Replace(string(raw), `"id":"`, `"id":"A`, 1)), testRP
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			raw, rp := build(t)
			if reg, err := rp.VerifyRegistration(raw, ch); err == nil {
				t.Fatalf("accepted: %+v", reg)
			}
		})
	}
}

// TestAssertionRefusals covers every assertion check with one changed
// input; the unchanged assertion passes.
func TestAssertionRefusals(t *testing.T) {
	t.Parallel()
	ch := challenge32()
	a := newAuthenticator(t, testRP, AlgES256, "7")
	key, err := ParseCOSEKey(a.key.cose())
	if err != nil {
		t.Fatal(err)
	}
	stored := Stored{Key: key, SignCount: 5, UserHandle: "7"}
	expect := Expect{Challenge: ch, HandleRequired: true}
	if _, err := testRP.Verify(mustParse(t, a.assert(t, ch, assertOpts{counter: 6})), stored, expect); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	empty := ""
	other := "8"
	trueBE := true
	cases := map[string]struct {
		opts   assertOpts
		stored Stored
		expect Expect
		want   error
	}{
		"counter equal":          {assertOpts{counter: 5}, stored, expect, errCounter},
		"counter lower":          {assertOpts{counter: 4}, stored, expect, errCounter},
		"counter zero after use": {assertOpts{counter: 0}, stored, expect, errCounter},
		"no user verification":   {assertOpts{counter: 6, flags: FlagUP}, stored, expect, errUser},
		"no user presence":       {assertOpts{counter: 6, flags: FlagUV}, stored, expect, errUser},
		"BS without BE":          {assertOpts{counter: 6, flags: FlagUP | FlagUV | FlagBS}, stored, expect, errAuthData},
		"BE appeared":            {assertOpts{counter: 6, flags: FlagUP | FlagUV | FlagBE}, Stored{Key: key, SignCount: 5, UserHandle: "7", BackupEligible: new(false)}, expect, errBackup},
		"BE disappeared":         {assertOpts{counter: 6}, Stored{Key: key, SignCount: 5, UserHandle: "7", BackupEligible: &trueBE}, expect, errBackup},
		"other user handle":      {assertOpts{counter: 6, handle: &other}, stored, expect, errHandle},
		"missing handle":         {assertOpts{counter: 6, handle: &empty}, stored, expect, errHandle},
		"wrong origin":           {assertOpts{counter: 6, origin: "http://localhost:4174"}, stored, expect, errClientData},
		"create instead of get":  {assertOpts{counter: 6, typ: typeCreate}, stored, expect, errClientData},
		"cross origin":           {assertOpts{counter: 6, extra: map[string]any{"crossOrigin": true}}, stored, expect, errClientData},
		"top origin":             {assertOpts{counter: 6, extra: map[string]any{"topOrigin": "https://evil.test"}}, stored, expect, errClientData},
		"token binding":          {assertOpts{counter: 6, extra: map[string]any{"tokenBinding": map[string]any{"status": "not-supported"}}}, stored, expect, errClientData},
		"other challenge":        {assertOpts{counter: 6}, stored, Expect{Challenge: bytes.Repeat([]byte{8}, 32)}, errClientData},
		"empty challenge":        {assertOpts{counter: 6}, stored, Expect{}, errClientData},
		"duplicate challenge member": {assertOpts{counter: 6, clientData: func(b []byte) []byte {
			return append(b[:len(b)-1], []byte(`,"challenge":"AAAA"}`)...)
		}}, stored, expect, errClientData},
		"invalid UTF-8 in client data": {assertOpts{counter: 6, clientData: func(b []byte) []byte {
			return append(b[:len(b)-1], []byte(",\"x\":\"\xff\"}")...)
		}}, stored, expect, errClientData},
		"truncated authenticator data": {assertOpts{counter: 6, authData: func(b []byte) []byte { return b[:36] }}, stored, expect, errAuthData},
		"trailing authenticator data":  {assertOpts{counter: 6, authData: func(b []byte) []byte { return append(b, 0) }}, stored, expect, errAuthData},
		"extension flag without map":   {assertOpts{counter: 6, flags: FlagUP | FlagUV | FlagED}, stored, expect, errAuthData},
		"other rp id": {assertOpts{counter: 6, authData: func(b []byte) []byte {
			c := bytes.Clone(b)
			c[0] ^= 1
			return c
		}}, stored, expect, errRPID},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := testRP.Verify(mustParse(t, a.assert(t, ch, c.opts)), c.stored, c.expect)
			if !errors.Is(err, c.want) {
				t.Fatalf("%v, want %v", err, c.want)
			}
		})
	}
	// Extensions are accepted when well-formed.
	withExt := a.assert(t, ch, assertOpts{counter: 7, flags: FlagUP | FlagUV | FlagED, authData: func(b []byte) []byte {
		return append(b, cborEncode([]cborPair{{"credProps", []cborPair{{"rk", true}}}})...)
	}})
	if _, err := testRP.Verify(mustParse(t, withExt), stored, expect); err != nil {
		t.Fatalf("extension map: %v", err)
	}
	// A signature of another credential fails.
	b := newAuthenticator(t, testRP, AlgES256, "7")
	b.id = a.id
	if _, err := testRP.Verify(mustParse(t, b.assert(t, ch, assertOpts{counter: 9})), stored, expect); !errors.Is(err, errSignature) {
		t.Fatalf("foreign key: %v", err)
	}
	// Without a required handle, a missing one passes (MFA and step-up name
	// the account before the ceremony).
	if _, err := testRP.Verify(mustParse(t, a.assert(t, ch, assertOpts{counter: 10, handle: &empty})), stored, Expect{Challenge: ch}); err != nil {
		t.Fatalf("missing handle with allowCredentials: %v", err)
	}
}

func TestParseAssertionRefusals(t *testing.T) {
	t.Parallel()
	for name, raw := range map[string]string{
		"not json":       `{`,
		"bad base64":     `{"id":"AA","rawId":"AA","type":"public-key","response":{"clientDataJSON":"!!","authenticatorData":"","signature":""}}`,
		"padding inside": `{"id":"AA","rawId":"A=A","type":"public-key","response":{}}`,
		"empty id":       `{"id":"","rawId":"","type":"public-key","response":{}}`,
		"long id":        `{"id":"` + strings.Repeat("A", 1366) + `","rawId":"` + strings.Repeat("A", 1366) + `","type":"public-key","response":{}}`,
		"duplicate id":   `{"id":"AA","id":"AA","rawId":"AA","type":"public-key","response":{}}`,
	} {
		if _, err := ParseAssertion(jsontext.Value(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestReason(t *testing.T) {
	t.Parallel()
	for err, want := range map[error]string{
		errCounter: "counter", refused(errSignature): "signature", fault.Wrap(fault.InvalidRequest, errClientData, "x"): "client_data",
		errLimit: "conflict", errors.New("disk"): "other", refused(errNotFound): "unknown_credential",
	} {
		if got := Reason(err); got != want {
			t.Errorf("%v: %q, want %q", err, got, want)
		}
	}
}
