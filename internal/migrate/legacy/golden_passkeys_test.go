package legacy

import (
	"encoding/base64"
	"encoding/json/jsontext"
	"strconv"
	"testing"

	"github.com/bifrost0x/webssh/internal/auth/webauthn"
)

type webauthnVector struct {
	CredentialRowID   int64           `json:"credential_row_id"`
	Name              string          `json:"name"`
	COSEAlg           int64           `json:"cose_alg"`
	StoredSignCount   int64           `json:"stored_sign_count"`
	AssertionCount    int64           `json:"assertion_sign_count"`
	ChallengeB64URL   string          `json:"challenge_b64url"`
	ExpectedOrigin    string          `json:"expected_origin"`
	ExpectedRPID      string          `json:"expected_rp_id"`
	AssertionResponse jsontext.Value  `json:"assertion_response"`
	Flags             map[string]bool `json:"flags"`
}

func b64url(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// verifyVector checks a golden assertion with the passkey capability's
// verifier against a stored credential.
func verifyVector(t *testing.T, vec webauthnVector, userID int64, coseKey []byte, storedCount int64) (uint32, error) {
	t.Helper()
	key, err := webauthn.ParseCOSEKey(coseKey)
	if err != nil {
		return 0, err
	}
	a, err := webauthn.ParseAssertion(vec.AssertionResponse)
	if err != nil {
		return 0, err
	}
	challenge, err := b64url(vec.ChallengeB64URL)
	if err != nil {
		t.Fatal(err)
	}
	rp := webauthn.RelyingParty{ID: vec.ExpectedRPID, Origin: vec.ExpectedOrigin, Name: "WebSSH"}
	v, err := rp.Verify(a, webauthn.Stored{Key: key, SignCount: uint32(storedCount), UserHandle: itoa(userID)}, // #nosec G115 -- counters of the fixture fit
		webauthn.Expect{Challenge: challenge})
	return v.SignCount, err
}

func itoa(id int64) string { return strconv.FormatInt(id, 10) }

// The legacy reader yields every passkey of the golden data set with a key
// the passkey capability parses; each golden assertion verifies against
// it with the configured RP ID and origin, a tampered one does not.
func TestGoldenPasskeys(t *testing.T) {
	t.Parallel()
	passkeys, err := golden.source.Passkeys(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	byID := map[int64]Passkey{}
	for _, p := range passkeys {
		byID[p.ID] = p
	}
	deleted := golden.manifest.Values.EdgeCases.PasskeyDeleted.ID
	if _, ok := byID[deleted]; ok {
		t.Fatal("deleted passkey is present")
	}
	owner := goldenUserByName(t, "passkey_user").ID
	algs := map[int64]bool{}
	for _, vec := range golden.manifest.Values.WebAuthnVectors {
		if vec.CredentialRowID == deleted {
			continue
		}
		pk, ok := byID[vec.CredentialRowID]
		if !ok || pk.Name != vec.Name || pk.PublicKey.Alg != vec.COSEAlg || pk.SignCount != vec.StoredSignCount || pk.UserID != owner {
			t.Fatalf("%s: row %+v", vec.Name, pk)
		}
		count, err := verifyVector(t, vec, owner, pk.COSEKey, pk.SignCount)
		if err != nil || int64(count) != vec.AssertionCount {
			t.Fatalf("%s: count %d, %v", vec.Name, count, err)
		}
		if _, err := verifyVector(t, vec, owner+1, pk.COSEKey, pk.SignCount); err == nil {
			t.Fatalf("%s: accepted for another user handle", vec.Name)
		}
		algs[vec.COSEAlg] = true
	}
	if len(algs) != 3 || !algs[webauthn.AlgES256] || !algs[webauthn.AlgRS256] || !algs[webauthn.AlgEdDSA] {
		t.Fatalf("algorithms covered: %v", algs)
	}
}
