package legacy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"

	"github.com/bifrost0x/webssh/internal/auth/oidc"
	"github.com/bifrost0x/webssh/internal/store"
)

// AddOIDCIdentities registers the step of entity E05 in place of its
// pending entry: the build that wires OIDC sign-in migrates the
// identities.
func AddOIDCIdentities(r *Registry) error {
	r.Schemas(oidc.Schema())
	return r.TakeOver(GroupAccounts, func() Step { return &oidcIdentitiesStep{} })
}

// oidcIdentitiesStep migrates entity E05: every oidc_identities row
// verbatim (row id, account, issuer, subject, created_at) into
// authoidc_identities, so a sign-in with the same provider reaches the
// same account. Rows of deleted accounts stay in the legacy database.
type oidcIdentitiesStep struct {
	rows []oidc.Imported
	ids  map[int64]bool
}

func (*oidcIdentitiesStep) Entity() string { return "E05" }

func (*oidcIdentitiesStep) Version() int { return 1 }

// OIDCIdentities reads oidc_identities in row order.
func (s *Source) OIDCIdentities(ctx context.Context) ([]oidc.Imported, error) {
	if !s.schema.HasTable("oidc_identities") {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, user_id, issuer, subject, created_at FROM oidc_identities ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("legacy: read oidc identities: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []oidc.Imported
	for rows.Next() {
		var in oidc.Imported
		var created any
		if err := rows.Scan(&in.ID, &in.UserID, &in.Issuer, &in.Subject, &created); err != nil {
			return nil, fmt.Errorf("legacy: read oidc identities: %w", err)
		}
		if in.CreatedAt, err = dbTime(dbText(created)); err != nil {
			return nil, fmt.Errorf("legacy: oidc identity %d: %w", in.ID, err)
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

func (s *oidcIdentitiesStep) Read(ctx context.Context, src *Source) error {
	var err error
	if s.rows, err = src.OIDCIdentities(ctx); err != nil {
		return err
	}
	seen := map[[2]string]int64{}
	for _, in := range s.rows {
		key := [2]string{in.Issuer, in.Subject}
		if first, dup := seen[key]; dup {
			return &StopError{Code: CodeStepFailed, Entity: "E05",
				Message: fmt.Sprintf("OIDC identities %d and %d have the same issuer and subject", first, in.ID)}
		}
		seen[key] = in.ID
	}
	_, s.ids, err = accountIDs(ctx, src)
	return err
}

func (s *oidcIdentitiesStep) kept() []oidc.Imported {
	return slices.DeleteFunc(slices.Clone(s.rows), func(in oidc.Imported) bool { return !s.ids[in.UserID] })
}

func (s *oidcIdentitiesStep) Write(ctx context.Context, tx *store.Tx, _ Sealer) error {
	for _, in := range s.kept() {
		if err := oidc.ImportTx(ctx, tx, in); err != nil {
			return &StepError{UserID: in.UserID, Record: fmt.Sprint(in.ID), Err: err}
		}
	}
	return nil
}

// Verify reads the identities back and checks that each one resolves to
// its account through the sign-in lookup (issuer and subject).
func (s *oidcIdentitiesStep) Verify(ctx context.Context, tx *store.Tx, _ Opener) error {
	got, err := oidc.ImportedTx(ctx, tx)
	if err != nil {
		return err
	}
	want := s.kept()
	if len(got) != len(want) {
		return fmt.Errorf("legacy: %d OIDC identities stored, %d expected", len(got), len(want))
	}
	for i := range want {
		if !got[i].CreatedAt.Equal(want[i].CreatedAt) || got[i].ID != want[i].ID || got[i].UserID != want[i].UserID ||
			got[i].Issuer != want[i].Issuer || got[i].Subject != want[i].Subject {
			return fmt.Errorf("legacy: OIDC identity %d differs after the migration", want[i].ID)
		}
		var userID int64
		err := tx.QueryRowContext(ctx, `SELECT user_id FROM authoidc_identities WHERE issuer = ? AND subject = ?`,
			want[i].Issuer, want[i].Subject).Scan(&userID)
		if errors.Is(err, sql.ErrNoRows) || err == nil && userID != want[i].UserID {
			return fmt.Errorf("legacy: OIDC identity %d does not resolve to its account", want[i].ID)
		}
		if err != nil {
			return fmt.Errorf("legacy: verify OIDC identity %d: %w", want[i].ID, err)
		}
	}
	return nil
}

func (s *oidcIdentitiesStep) Report() StepReport {
	r := StepReport{Entity: "E05", Version: 1, Read: len(s.rows)}
	for _, in := range s.rows {
		if s.ids[in.UserID] {
			r.Written++
		} else {
			r.Notes = append(r.Notes, fmt.Sprintf("OIDC identity %d belongs to a deleted account and stays in app.db", in.ID))
		}
	}
	return r
}
