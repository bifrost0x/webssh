package legacy

import (
	"bytes"
	"context"
	json "encoding/json/v2"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/store"
)

// testPasskeys stands in for the adapter of internal/auth/webauthn: it
// stores what the step hands over in a table of the owner webauthn.
type testPasskeys struct{}

func (testPasskeys) Schema() store.Schema {
	return store.Schema{Owner: "webauthn", Migrations: []store.Migration{{Version: 1, SQL: `CREATE TABLE webauthn_test_credentials (
	id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, user_handle TEXT NOT NULL, credential_id BLOB NOT NULL UNIQUE,
	cose_key BLOB NOT NULL, algorithm INTEGER NOT NULL, sign_count INTEGER NOT NULL, transports TEXT NOT NULL,
	name TEXT NOT NULL, created_us INTEGER NOT NULL, last_used_us INTEGER) STRICT;`}}}
}

func (testPasskeys) ImportPasskeyTx(ctx context.Context, tx *store.Tx, p ImportedPasskey) error {
	transports, err := json.Marshal(p.Transports)
	if err != nil {
		return err
	}
	var used any
	if !p.LastUsedAt.IsZero() {
		used = p.LastUsedAt.UnixMicro()
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO webauthn_test_credentials VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, p.ID, p.UserID,
		p.UserHandle, p.CredentialID, p.COSEKey, p.Algorithm, p.SignCount, string(transports), p.Name, p.CreatedAt.UnixMicro(), used)
	return err
}

func (testPasskeys) PasskeysTx(ctx context.Context, tx *store.Tx, userID int64) ([]ImportedPasskey, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, user_id, user_handle, credential_id, cose_key, algorithm, sign_count, transports,
		name, created_us, last_used_us FROM webauthn_test_credentials WHERE user_id = ? ORDER BY id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ImportedPasskey
	for rows.Next() {
		var p ImportedPasskey
		var transports string
		var created int64
		var used *int64
		if err := rows.Scan(&p.ID, &p.UserID, &p.UserHandle, &p.CredentialID, &p.COSEKey, &p.Algorithm, &p.SignCount,
			&transports, &p.Name, &created, &used); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(transports), &p.Transports); err != nil {
			return nil, err
		}
		p.CreatedAt = time.UnixMicro(created).UTC()
		if used != nil {
			p.LastUsedAt = time.UnixMicro(*used).UTC()
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// E10: with a passkey store, every golden assertion vector verifies
// against the migrated record (key, counter rule, user handle), a
// tampered signature fails, and the deleted passkey is absent.
func TestM1GoldenPasskeys(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	m := migrateM1(t, dir, golden.manifest.SecretKey.Value, M1{Passkeys: testPasskeys{}})
	owner := goldenUserByName(t, "passkey_user").ID
	var stored []ImportedPasskey
	err := m.db.Read(t.Context(), func(tx *store.Tx) error {
		var err error
		stored, err = testPasskeys{}.PasskeysTx(t.Context(), tx, owner)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	byID := map[int64]ImportedPasskey{}
	for _, p := range stored {
		byID[p.ID] = p
		if p.UserHandle != strconv.FormatInt(owner, 10) {
			t.Errorf("user handle %q", p.UserHandle)
		}
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
		key, alg, err := ParseCOSEKey(p.COSEKey)
		if err != nil || alg != vec.COSEAlg {
			t.Fatalf("%s: %v", vec.Name, err)
		}
		r := vec.AssertionResponse.Response
		authData, err1 := b64url(r.AuthenticatorData)
		clientData, err2 := b64url(r.ClientDataJSON)
		sig, err3 := b64url(r.Signature)
		handle, err4 := b64url(r.UserHandle)
		challenge, err5 := b64url(vec.ChallengeB64URL)
		rawID, err6 := b64url(vec.AssertionResponse.RawID)
		if err := errors.Join(err1, err2, err3, err4, err5, err6); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(rawID, p.CredentialID) || string(handle) != p.UserHandle {
			t.Fatalf("%s: credential id or user handle differ", vec.Name)
		}
		check := prototypeAssertion{rpID: vec.ExpectedRPID, origin: vec.ExpectedOrigin, challenge: challenge, userID: owner}
		count, err := check.verify(key, alg, p.SignCount, authData, clientData, sig, p.UserHandle)
		if err != nil || int64(count) != vec.AssertionCount {
			t.Fatalf("%s: %d, %v", vec.Name, count, err)
		}
		sig[len(sig)-1] ^= 1
		if _, err := check.verify(key, alg, p.SignCount, authData, clientData, sig, p.UserHandle); err == nil {
			t.Fatalf("%s: tampered signature accepted", vec.Name)
		}
		verified++
	}
	if verified != 3 {
		t.Fatalf("verified %d passkeys", verified)
	}
	for _, e := range m.report.Pending {
		if e.Entity == "E10" {
			t.Fatal("E10 is pending although a store was given")
		}
	}
}

// A passkey whose COSE key does not parse is STOP naming E10.
func TestM1PasskeyInvalidCOSE(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	execLegacySQL(t, dir, `UPDATE webauthn_credentials SET public_key = X'A10102' WHERE id = (SELECT min(id) FROM webauthn_credentials)`)
	before := legacySnapshot(t, dir)
	_, err := startClosed(m1Options(t, dir, M1{Passkeys: testPasskeys{}}))
	assertStop(t, err, "E10")
	assertUntouched(t, dir, before)
	assertNoGoDatabase(t, dir)
}

