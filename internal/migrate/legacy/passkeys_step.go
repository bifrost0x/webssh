package legacy

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/bifrost0x/webssh/internal/store"
)

// ImportedPasskey is one passkey of the Python release (entity E10) in
// the form the passkey capability stores: the credential id and the COSE
// key as raw bytes, the counter, the transports and the name unchanged.
// UserHandle is the ASCII decimal user id the authenticator returns
// (I-02).
type ImportedPasskey struct {
	ID           int64
	UserID       int64
	UserHandle   string
	CredentialID []byte
	COSEKey      []byte
	Algorithm    int64
	SignCount    int64
	Transports   []string
	Name         string
	CreatedAt    time.Time
	LastUsedAt   time.Time // zero if never used
}

// PasskeyStore takes over migrated passkeys. internal/auth/webauthn
// provides it through an adapter of the composition root; the migration
// declares it, as the consumer.
type PasskeyStore interface {
	Schema() store.Schema
	ImportPasskeyTx(ctx context.Context, tx *store.Tx, p ImportedPasskey) error
	// PasskeysTx returns the stored passkeys of userID ordered by id, for
	// the verification.
	PasskeysTx(ctx context.Context, tx *store.Tx, userID int64) ([]ImportedPasskey, error)
}

// passkeysStep migrates entity E10 through a PasskeyStore. Every COSE key
// is parsed once to prove its algorithm (ES256, RS256, EdDSA) and curve.
type passkeysStep struct {
	store PasskeyStore
	keys  []ImportedPasskey
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
		k := ImportedPasskey{ID: p.ID, UserID: p.UserID, UserHandle: strconv.FormatInt(p.UserID, 10),
			CredentialID: p.CredentialID, COSEKey: p.COSEKey, Algorithm: p.Algorithm, SignCount: p.SignCount,
			Transports: p.Transports, Name: p.Name}
		if k.CreatedAt, err = dbTime(sql.NullString{String: p.CreatedAt, Valid: true}); err == nil {
			k.LastUsedAt, err = dbTime(used[p.ID])
		}
		if err != nil {
			return &StepError{UserID: p.UserID, Record: fmt.Sprint(p.ID), Err: err}
		}
		s.keys = append(s.keys, k)
	}
	return nil
}

func passkeyLastUse(ctx context.Context, src *Source) (map[int64]sql.NullString, error) {
	out := map[int64]sql.NullString{}
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
	for _, k := range s.keys {
		if err := s.store.ImportPasskeyTx(ctx, tx, k); err != nil {
			return &StepError{UserID: k.UserID, Record: fmt.Sprint(k.ID), Err: err}
		}
	}
	return nil
}

func (s *passkeysStep) Verify(ctx context.Context, tx *store.Tx, _ Opener) error {
	byUser := map[int64][]ImportedPasskey{}
	for _, k := range s.keys {
		byUser[k.UserID] = append(byUser[k.UserID], k)
	}
	for user, want := range byUser {
		got, err := s.store.PasskeysTx(ctx, tx, user)
		if err != nil {
			return &StepError{UserID: user, Err: err}
		}
		if !slices.EqualFunc(got, want, samePasskey) {
			return &StepError{UserID: user, Err: errors.New("legacy: the stored passkeys differ")}
		}
		for _, k := range got {
			if _, alg, err := ParseCOSEKey(k.COSEKey); err != nil || alg != k.Algorithm {
				return &StepError{UserID: user, Record: fmt.Sprint(k.ID), Err: errors.Join(errors.New("legacy: stored COSE key"), err)}
			}
		}
	}
	return nil
}

func samePasskey(a, b ImportedPasskey) bool {
	return a.ID == b.ID && a.UserID == b.UserID && a.UserHandle == b.UserHandle && bytes.Equal(a.CredentialID, b.CredentialID) &&
		bytes.Equal(a.COSEKey, b.COSEKey) && a.Algorithm == b.Algorithm && a.SignCount == b.SignCount &&
		slices.Equal(a.Transports, b.Transports) && a.Name == b.Name && a.CreatedAt.Equal(b.CreatedAt) && a.LastUsedAt.Equal(b.LastUsedAt)
}

func (s *passkeysStep) Report() StepReport {
	return StepReport{Entity: "E10", Version: 1, Read: len(s.keys), Written: len(s.keys)}
}

// countPasskeys counts the passkeys left in place when the build has no
// passkey capability.
func countPasskeys(ctx context.Context, src *Source) (int, error) {
	return countTable(ctx, src, "webauthn_credentials")
}
