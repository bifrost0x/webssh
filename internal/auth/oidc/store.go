package oidc

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
)

// Schema returns the identity table (E05): one row per linked identity,
// unique (issuer, subject), several per account as in the Python
// release. Times are microseconds since the Unix epoch (UTC); id keeps
// the Python row id, which the administration addresses.
func Schema() store.Schema {
	return store.Schema{Owner: Owner, Migrations: []store.Migration{{Version: 1, SQL: `
CREATE TABLE authoidc_identities (
	id INTEGER PRIMARY KEY,
	user_id INTEGER NOT NULL CHECK (user_id > 0),
	issuer TEXT NOT NULL,
	subject TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	UNIQUE (issuer, subject)
) STRICT;
CREATE INDEX authoidc_identities_user ON authoidc_identities (user_id, created_at, id);
`}}}
}

// Links is the identity table of the issuer (auth.IdentityLinks). OIDC
// never creates or manages an account: Provision is always refused.
type Links struct {
	DB  *store.DB
	Now func() time.Time
}

var _ auth.IdentityLinks = (*Links)(nil)

func (l *Links) now() time.Time {
	if l.Now != nil {
		return l.Now().UTC()
	}
	return time.Now().UTC()
}

// Account returns the account of an identity, found only by issuer and
// subject; an unlinked identity is fault.NotFound.
func (l *Links) Account(ctx context.Context, id auth.Identity) (int64, error) {
	var userID int64
	err := l.DB.Read(ctx, func(tx *store.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT user_id FROM authoidc_identities WHERE issuer = ? AND subject = ?`,
			id.Issuer, id.Subject).Scan(&userID)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return 0, fault.New(fault.NotFound, "")
	}
	if err != nil {
		return 0, fmt.Errorf("oidc: read identity: %w", err)
	}
	return userID, nil
}

// Provision implements auth.IdentityLinks: OIDC never provisions.
func (*Links) Provision(context.Context, auth.Identity) (int64, error) {
	return 0, fault.New(fault.Forbidden, "")
}

// LinkTx links the identity to userID. An identity linked anywhere,
// to this account too, is fault.Conflict; it never moves.
func (l *Links) LinkTx(ctx context.Context, tx *store.Tx, userID int64, id auth.Identity) (auth.LinkedIdentity, error) {
	if userID <= 0 || id.Issuer == "" || id.Subject == "" || len(id.Issuer) > 512*4 || len(id.Subject) > 512*4 {
		return auth.LinkedIdentity{}, fault.New(fault.InvalidRequest, "")
	}
	now := l.now()
	res, err := tx.ExecContext(ctx, `INSERT INTO authoidc_identities (user_id, issuer, subject, created_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (issuer, subject) DO NOTHING`, userID, id.Issuer, id.Subject, now.UnixMicro())
	if err != nil {
		return auth.LinkedIdentity{}, fmt.Errorf("oidc: link identity: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return auth.LinkedIdentity{}, errors.Join(fault.New(fault.Conflict, "OIDC identity is already linked"), err)
	}
	rowID, err := res.LastInsertId()
	if err != nil {
		return auth.LinkedIdentity{}, fmt.Errorf("oidc: link identity: %w", err)
	}
	return auth.LinkedIdentity{ID: rowID, UserID: userID, Provider: auth.ProviderOIDC, Issuer: id.Issuer, Subject: id.Subject, CreatedAt: now}, nil
}

// Link is LinkTx in its own transaction.
func (l *Links) Link(ctx context.Context, userID int64, id auth.Identity) (auth.LinkedIdentity, error) {
	var out auth.LinkedIdentity
	err := l.DB.Write(ctx, func(tx *store.Tx) error {
		var err error
		out, err = l.LinkTx(ctx, tx, userID, id)
		return err
	})
	return out, err
}

// Unlink removes one identity of the account; another account's or an
// unknown identity is fault.NotFound.
func (l *Links) Unlink(ctx context.Context, userID, identityID int64) error {
	return l.DB.Write(ctx, func(tx *store.Tx) error { return l.UnlinkTx(ctx, tx, userID, identityID) })
}

// UnlinkTx is Unlink in the caller's transaction.
func (l *Links) UnlinkTx(ctx context.Context, tx *store.Tx, userID, identityID int64) error {
	res, err := tx.ExecContext(ctx, `DELETE FROM authoidc_identities WHERE id = ? AND user_id = ?`, identityID, userID)
	if err != nil {
		return fmt.Errorf("oidc: unlink identity: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("oidc: unlink identity: %w", err)
	} else if n != 1 {
		return fault.New(fault.NotFound, "OIDC identity not found")
	}
	return nil
}

// List returns the identities of the account, oldest first.
func (l *Links) List(ctx context.Context, userID int64) ([]auth.LinkedIdentity, error) {
	var out []auth.LinkedIdentity
	err := l.DB.Read(ctx, func(tx *store.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id, user_id, issuer, subject, created_at FROM authoidc_identities
			WHERE user_id = ? ORDER BY created_at, id`, userID)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			li := auth.LinkedIdentity{Provider: auth.ProviderOIDC}
			var created int64
			if err := rows.Scan(&li.ID, &li.UserID, &li.Issuer, &li.Subject, &created); err != nil {
				return err
			}
			li.CreatedAt = time.UnixMicro(created).UTC()
			out = append(out, li)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("oidc: list identities: %w", err)
	}
	return out, nil
}

// HasIdentity reports whether the account has any OIDC identity.
func (l *Links) HasIdentity(ctx context.Context, userID int64) (bool, error) {
	var n int
	err := l.DB.Read(ctx, func(tx *store.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM authoidc_identities WHERE user_id = ?`, userID).Scan(&n)
	})
	if err != nil {
		return false, fmt.Errorf("oidc: read identities: %w", err)
	}
	return n > 0, nil
}

// Imported is one identity of the legacy migration (E05).
type Imported struct {
	ID, UserID      int64
	Issuer, Subject string
	CreatedAt       time.Time
}

// ImportTx stores a legacy identity verbatim, keeping its row id. A
// second identity with the same issuer and subject fails (the
// migration stops on a uniqueness violation).
func ImportTx(ctx context.Context, tx *store.Tx, in Imported) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO authoidc_identities (id, user_id, issuer, subject, created_at) VALUES (?, ?, ?, ?, ?)`,
		in.ID, in.UserID, in.Issuer, in.Subject, in.CreatedAt.UnixMicro())
	if err != nil {
		return fmt.Errorf("oidc: import identity %d: %w", in.ID, err)
	}
	return nil
}

// ImportedTx reads every identity back for the migration's verification.
func ImportedTx(ctx context.Context, tx *store.Tx) ([]Imported, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, user_id, issuer, subject, created_at FROM authoidc_identities ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("oidc: read identities: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Imported
	for rows.Next() {
		var in Imported
		var created int64
		if err := rows.Scan(&in.ID, &in.UserID, &in.Issuer, &in.Subject, &created); err != nil {
			return nil, fmt.Errorf("oidc: read identities: %w", err)
		}
		in.CreatedAt = time.UnixMicro(created).UTC()
		out = append(out, in)
	}
	return out, rows.Err()
}
