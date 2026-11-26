package webauthn

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"os"
	"strconv"
	"testing"
)

// TestChromiumCeremonies verifies registrations and sign-ins that Chromium
// produced with its virtual authenticator (CTAP2, resident key, user
// verification) for ES256, EdDSA and RS256, with attestation "none" (the
// browser strips the statement) and "direct" (a packed statement), as
// webauthn.js serializes them. The capture page used the options of this
// package on http://localhost.
func TestChromiumCeremonies(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("testdata/chromium-virtual-authenticator.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Captures []struct {
			Alg                   int64          `json:"alg"`
			Attestation           string         `json:"attestation"`
			Origin                string         `json:"origin"`
			RegistrationChallenge string         `json:"registration_challenge"`
			Registration          jsontext.Value `json:"registration"`
			AssertionChallenge    string         `json:"assertion_challenge"`
			Assertion             jsontext.Value `json:"assertion"`
		} `json:"captures"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Captures) != 6 {
		t.Fatalf("%d captures", len(file.Captures))
	}
	for _, c := range file.Captures {
		t.Run(strconv.FormatInt(c.Alg, 10)+"/"+c.Attestation, func(t *testing.T) {
			t.Parallel()
			rp := RelyingParty{ID: "localhost", Name: "WebSSH", Origin: c.Origin}
			regCh, _ := decodeB64URL(c.RegistrationChallenge)
			reg, err := rp.VerifyRegistration(c.Registration, regCh)
			if err != nil {
				t.Fatalf("registration: %v", err)
			}
			wantFormat := FormatNone
			if c.Attestation == "direct" {
				wantFormat = FormatPacked
			}
			if reg.Alg != c.Alg || reg.Format != wantFormat {
				t.Fatalf("registration %+v", reg)
			}
			key, err := ParseCOSEKey(reg.COSEKey)
			if err != nil {
				t.Fatal(err)
			}
			asn, err := ParseAssertion(c.Assertion)
			if err != nil {
				t.Fatal(err)
			}
			authCh, _ := decodeB64URL(c.AssertionChallenge)
			be := reg.Flags&FlagBE != 0
			stored := Stored{Key: key, SignCount: reg.SignCount, UserHandle: "7", BackupEligible: &be}
			if _, err := rp.Verify(asn, stored, Expect{Challenge: authCh, HandleRequired: true}); err != nil {
				t.Fatalf("assertion: %v", err)
			}
			if _, err := (RelyingParty{ID: "localhost", Origin: "https://localhost"}).Verify(asn, stored, Expect{Challenge: authCh}); err == nil {
				t.Fatal("other origin accepted")
			}
			if _, err := rp.Verify(asn, Stored{Key: key, SignCount: reg.SignCount, UserHandle: "8"}, Expect{Challenge: authCh}); err == nil {
				t.Fatal("other user handle accepted")
			}
		})
	}
}
