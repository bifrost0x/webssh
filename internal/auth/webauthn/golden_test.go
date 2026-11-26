package webauthn

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"os"
	"strconv"
	"testing"
)

// The golden data set (tests/golden) holds passkeys registered and used
// through the unmodified Python release. Every expected value comes from
// its manifest.
const goldenManifest = "../../../tests/golden/fixture/manifest.json"

type goldenVector struct {
	RowID          int64           `json:"credential_row_id"`
	Name           string          `json:"name"`
	COSEAlg        int64           `json:"cose_alg"`
	StoredCount    uint32          `json:"stored_sign_count"`
	AssertionCount uint32          `json:"assertion_sign_count"`
	Challenge      string          `json:"challenge_b64url"`
	Origin         string          `json:"expected_origin"`
	RPID           string          `json:"expected_rp_id"`
	Flags          map[string]bool `json:"flags"`
	Registration   jsontext.Value  `json:"registration_response"`
	Assertion      jsontext.Value  `json:"assertion_response"`
}

type golden struct {
	RP      RelyingParty
	UserID  int64
	Vectors []goldenVector
}

func loadGolden(t *testing.T) golden {
	t.Helper()
	raw, err := os.ReadFile(goldenManifest)
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Environment map[string]string `json:"environment"`
		Values      struct {
			Users map[string]struct {
				ID int64 `json:"id"`
			} `json:"users"`
			Vectors []goldenVector `json:"webauthn_vectors"`
		} `json:"values"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	g := golden{
		RP:      RelyingParty{ID: m.Environment["WEBAUTHN_RP_ID"], Name: "WebSSH", Origin: m.Environment["WEBAUTHN_ORIGIN"]},
		UserID:  m.Values.Users["passkey_user"].ID,
		Vectors: m.Values.Vectors,
	}
	if g.RP.ID == "" || g.RP.Origin == "" || g.UserID == 0 || len(g.Vectors) != 4 {
		t.Fatalf("manifest: %+v", g)
	}
	return g
}

// registrationChallenge returns the challenge the Python release issued,
// as recorded in the client data.
func registrationChallenge(t *testing.T, reg jsontext.Value) []byte {
	t.Helper()
	c, _, err := parseCredential(reg)
	if err != nil {
		t.Fatal(err)
	}
	cdj, err := decodeB64URL(c.Response.ClientDataJSON)
	if err != nil {
		t.Fatal(err)
	}
	var cd clientData
	if err := json.Unmarshal(cdj, &cd); err != nil {
		t.Fatal(err)
	}
	ch, err := decodeB64URL(cd.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	return ch
}

// TestGoldenPasskeys verifies the Python-registered passkeys (ES256, RS256,
// EdDSA, a synced one with BE/BS and counter 0, and one with BE only)
// with the configured RP ID and origin: the registration as the Python
// release received it, the recorded assertion against the stored counter,
// and the refusals for a replayed counter, another origin, another RP ID,
// another challenge, another user handle and a tampered signature.
func TestGoldenPasskeys(t *testing.T) {
	t.Parallel()
	g := loadGolden(t)
	algs := map[int64]bool{}
	for _, v := range g.Vectors {
		algs[v.COSEAlg] = true
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()
			reg, err := g.RP.VerifyRegistration(v.Registration, registrationChallenge(t, v.Registration))
			if err != nil {
				t.Fatalf("registration: %v", err)
			}
			if reg.Alg != v.COSEAlg || reg.Format != FormatNone || reg.Flags&FlagBE != 0 != v.Flags["BE"] {
				t.Fatalf("registration %+v", reg)
			}
			key, err := ParseCOSEKey(reg.COSEKey)
			if err != nil {
				t.Fatal(err)
			}
			asn, err := ParseAssertion(v.Assertion)
			if err != nil {
				t.Fatal(err)
			}
			if string(asn.CredentialID) != string(reg.CredentialID) {
				t.Fatal("assertion names another credential")
			}
			challenge, err := decodeB64URL(v.Challenge)
			if err != nil {
				t.Fatal(err)
			}
			be := reg.Flags&FlagBE != 0
			stored := Stored{Key: key, SignCount: v.StoredCount, UserHandle: strconv.FormatInt(g.UserID, 10), BackupEligible: &be}
			expect := Expect{Challenge: challenge, HandleRequired: true}
			res, err := g.RP.Verify(asn, stored, expect)
			if err != nil {
				t.Fatalf("assertion: %v", err)
			}
			if res.SignCount != v.AssertionCount || res.Flags&FlagBE != 0 != v.Flags["BE"] ||
				res.Flags&FlagBS != 0 != v.Flags["BS"] || res.Flags&FlagUV == 0 || res.Flags&FlagUP == 0 {
				t.Fatalf("result %+v", res)
			}
			// Migrated credentials carry no backup flag.
			legacy := stored
			legacy.BackupEligible = nil
			if _, err := g.RP.Verify(asn, legacy, expect); err != nil {
				t.Fatalf("migrated record: %v", err)
			}
			checks := map[string]struct {
				rp     RelyingParty
				stored Stored
				expect Expect
				want   error
			}{
				"other origin":    {RelyingParty{ID: g.RP.ID, Origin: "https://attacker.test"}, stored, expect, errClientData},
				"http origin":     {RelyingParty{ID: g.RP.ID, Origin: "http://" + g.RP.ID}, stored, expect, errClientData},
				"other rp id":     {RelyingParty{ID: "golden.test", Origin: g.RP.Origin}, stored, expect, errRPID},
				"other challenge": {g.RP, stored, Expect{Challenge: append([]byte{1}, challenge[1:]...)}, errClientData},
				"other user":      {g.RP, Stored{Key: key, SignCount: v.StoredCount, UserHandle: "8"}, expect, errHandle},
				"other key":       {g.RP, Stored{Key: otherKey(t, g, v), SignCount: v.StoredCount, UserHandle: stored.UserHandle}, expect, errSignature},
				"flipped be":      {g.RP, Stored{Key: key, UserHandle: stored.UserHandle, BackupEligible: new(!be)}, expect, errBackup},
			}
			if v.AssertionCount > 0 {
				replay := stored
				replay.SignCount = v.AssertionCount
				checks["replayed counter"] = struct {
					rp     RelyingParty
					stored Stored
					expect Expect
					want   error
				}{g.RP, replay, expect, errCounter}
			} else {
				// A synced passkey keeps counter 0; a stored non-zero
				// counter then refuses it (Python rule).
				ahead := stored
				ahead.SignCount = 1
				checks["counter went back to zero"] = struct {
					rp     RelyingParty
					stored Stored
					expect Expect
					want   error
				}{g.RP, ahead, expect, errCounter}
			}
			for name, c := range checks {
				if _, err := c.rp.Verify(asn, c.stored, c.expect); !errors.Is(err, c.want) {
					t.Errorf("%s: %v, want %v", name, err, c.want)
				}
			}
			bad := asn
			bad.signature = append([]byte(nil), asn.signature...)
			bad.signature[len(bad.signature)-1] ^= 1
			if _, err := g.RP.Verify(bad, stored, expect); !errors.Is(err, errSignature) {
				t.Errorf("tampered signature: %v", err)
			}
			if _, err := g.RP.VerifyRegistration(v.Registration, challenge); err == nil {
				t.Error("registration with the wrong challenge accepted")
			}
		})
	}
	if len(algs) != 3 || !algs[AlgES256] || !algs[AlgRS256] || !algs[AlgEdDSA] {
		t.Fatalf("algorithms covered: %v", algs)
	}
}

// otherKey returns the key of another golden credential.
func otherKey(t *testing.T, g golden, v goldenVector) PublicKey {
	t.Helper()
	for _, o := range g.Vectors {
		if o.RowID != v.RowID && o.COSEAlg == v.COSEAlg || o.RowID != v.RowID && v.COSEAlg != AlgES256 && o.COSEAlg == AlgES256 {
			reg, err := g.RP.VerifyRegistration(o.Registration, registrationChallenge(t, o.Registration))
			if err != nil {
				t.Fatal(err)
			}
			k, err := ParseCOSEKey(reg.COSEKey)
			if err != nil {
				t.Fatal(err)
			}
			return k
		}
	}
	t.Fatal("no other key")
	return PublicKey{}
}
