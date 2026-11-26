package legacy

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"

	"github.com/bifrost0x/webssh/internal/auth/webauthn"
	"github.com/bifrost0x/webssh/internal/store"
)

// passkeysStep migrates entity E10 into internal/auth/webauthn: the
// credential id and the COSE key byte for byte, the counter, transports
// and name. The passkey capability parses each COSE key (ES256, RS256,
// EdDSA and their curves) on read and again at import. The user handle
// stays the ASCII decimal user id (I-02), which the capability derives
// from the owner.
type passkeysStep struct {
	keys []webauthn.Imported
}

func (*passkeysStep) Entity() string { return "E10" }

func (*passkeysStep) Version() int { return 1 }

func (s *passkeysStep) Read(ctx context.Context, src *Source) error {
	rows, err := src.Passkeys(ctx)
	if err != nil {
		return err
	}
	used, err := passkeyLastUse(ctx, src)
	if err != nil {
		return err
	}
	for _, p := range rows {
		k := webauthn.Imported{ID: p.ID, UserID: p.UserID, CredentialID: p.CredentialID, COSEKey: p.COSEKey,
			SignCount: p.SignCount, Transports: p.Transports, Name: p.Name}
		if k.CreatedAt, err = dbTime(sql.NullString{String: p.CreatedAt, Valid: true}); err == nil {
			k.LastUsedAt, err = dbTime(used[p.ID])
		}
		if err != nil {
			return &StepError{UserID: p.UserID, Record: fmt.Sprint(p.ID), Err: err}
		}
		if k.Transports == nil {
			k.Transports = []string{}
		}
		s.keys = append(s.keys, k)
	}
	return nil
}

func passkeyLastUse(ctx context.Context, src *Source) (map[int64]sql.NullString, error) {
	out := map[int64]sql.NullString{}
	if !src.schema.HasTable("webauthn_credentials") {
		return out, nil
	}
	rows, err := src.db.QueryContext(ctx, `SELECT id, CAST(last_used_at AS TEXT) FROM webauthn_credentials`)
	if err != nil {
		return nil, fmt.Errorf("legacy: read passkeys: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var at sql.NullString
		if err := rows.Scan(&id, &at); err != nil {
			return nil, fmt.Errorf("legacy: read passkeys: %w", err)
		}
		out[id] = at
	}
	return out, rows.Err()
}

func (s *passkeysStep) Write(ctx context.Context, tx *store.Tx, _ Sealer) error {
	svc := &webauthn.Service{}
	for _, k := range s.keys {
		if err := svc.ImportTx(ctx, tx, k); err != nil {
			return &StepError{UserID: k.UserID, Record: fmt.Sprint(k.ID), Err: err}
		}
	}
	return nil
}

// Verify reads every account's passkeys back: the records are equal and
// each stored key parses to the algorithm the legacy key had.
func (s *passkeysStep) Verify(ctx context.Context, tx *store.Tx, _ Opener) error {
	byUser := map[int64][]webauthn.Imported{}
	for _, k := range s.keys {
		byUser[k.UserID] = append(byUser[k.UserID], k)
	}
	for user, want := range byUser {
		got, err := webauthn.ImportedTx(ctx, tx, user)
		if err != nil {
			return &StepError{UserID: user, Err: err}
		}
		if !slices.EqualFunc(got, want, samePasskey) {
			return &StepError{UserID: user, Err: errors.New("legacy: the stored passkeys differ")}
		}
		for i, k := range got {
			gotKey, err1 := webauthn.ParseCOSEKey(k.COSEKey)
			wantKey, err2 := webauthn.ParseCOSEKey(want[i].COSEKey)
			if err := errors.Join(err1, err2); err != nil || gotKey.Alg != wantKey.Alg {
				return &StepError{UserID: user, Record: fmt.Sprint(k.ID), Err: errors.Join(errors.New("legacy: stored COSE key"), err)}
			}
		}
	}
	return nil
}

func samePasskey(a, b webauthn.Imported) bool {
	return a.ID == b.ID && a.UserID == b.UserID && bytes.Equal(a.CredentialID, b.CredentialID) &&
		bytes.Equal(a.COSEKey, b.COSEKey) && a.SignCount == b.SignCount && slices.Equal(a.Transports, b.Transports) &&
		a.Name == b.Name && a.CreatedAt.Equal(b.CreatedAt) && a.LastUsedAt.Equal(b.LastUsedAt)
}

func (s *passkeysStep) Report() StepReport {
	return StepReport{Entity: "E10", Version: 1, Read: len(s.keys), Written: len(s.keys)}
}
