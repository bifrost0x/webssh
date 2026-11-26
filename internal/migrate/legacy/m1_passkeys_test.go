package legacy

import (
	"bytes"
	"strconv"
	"testing"

	"github.com/bifrost0x/webssh/internal/auth/webauthn"
	"github.com/bifrost0x/webssh/internal/store"
)

// E10: every golden assertion vector verifies with the passkey
// capability's verifier against the migrated record (key, counter rule,
// user handle); a replayed counter and a foreign user handle fail, and
// the deleted passkey is absent.
func TestM1GoldenPasskeys(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	m := migrateM1(t, dir, golden.manifest.SecretKey.Value, M1{})
	owner := goldenUserByName(t, "passkey_user").ID
	var stored []webauthn.Imported
	err := m.db.Read(t.Context(), func(tx *store.Tx) error {
		var err error
		stored, err = webauthn.ImportedTx(t.Context(), tx, owner)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	byID := map[int64]webauthn.Imported{}
	for _, p := range stored {
		byID[p.ID] = p
	}
	if _, ok := byID[golden.manifest.Values.EdgeCases.PasskeyDeleted.ID]; ok {
		t.Fatal("the deleted passkey was migrated")
	}
	verified := 0
	for _, vec := range golden.manifest.Values.WebAuthnVectors {
		p, ok := byID[vec.CredentialRowID]
		if !ok {
			continue
		}
		raw, _ := webauthn.ParseAssertion(vec.AssertionResponse)
		if !bytes.Equal(raw.CredentialID, p.CredentialID) || string(raw.UserHandle) != strconv.FormatInt(owner, 10) {
			t.Fatalf("%s: credential id or user handle differ", vec.Name)
		}
		count, err := verifyVector(t, vec, owner, p.COSEKey, p.SignCount)
		if err != nil || int64(count) != vec.AssertionCount {
			t.Fatalf("%s: %d, %v", vec.Name, count, err)
		}
		if vec.AssertionCount > 0 {
			if _, err := verifyVector(t, vec, owner, p.COSEKey, vec.AssertionCount); err == nil {
				t.Fatalf("%s: replayed counter accepted", vec.Name)
			}
		}
		if _, err := verifyVector(t, vec, owner+1, p.COSEKey, p.SignCount); err == nil {
			t.Fatalf("%s: foreign user handle accepted", vec.Name)
		}
		verified++
	}
	if verified != 3 {
		t.Fatalf("verified %d passkeys", verified)
	}
	for _, e := range m.report.Pending {
		if e.Entity == "E10" {
			t.Fatal("E10 is pending")
		}
	}
}

// A passkey whose COSE key does not parse is STOP naming E10.
func TestM1PasskeyInvalidCOSE(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	execLegacySQL(t, dir, `UPDATE webauthn_credentials SET public_key = X'A10102' WHERE id = (SELECT min(id) FROM webauthn_credentials)`)
	before := legacySnapshot(t, dir)
	_, err := startClosed(m1Options(t, dir, M1{}))
	assertStop(t, err, "E10")
	assertUntouched(t, dir, before)
	assertNoGoDatabase(t, dir)
}
