package ldap

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
)

// Schema is the store of the package. authldap_identities keeps the
// ldap_identities rows of the Python release verbatim (E03): the id, the
// provider and the canonical subject, which together are the binding.
// authldap_revalidation holds per account the last successful directory
// check and whether a check is required before any access (E37).
// Times are microseconds since the Unix epoch (UTC).
func Schema() store.Schema {
	return store.Schema{Owner: Owner, Migrations: []store.Migration{{Version: 1, SQL: `
CREATE TABLE authldap_identities (
	id                 INTEGER PRIMARY KEY,
	user_id            INTEGER NOT NULL UNIQUE CHECK (user_id > 0),
	provider           TEXT NOT NULL,
	subject            TEXT NOT NULL,
	directory_username TEXT NOT NULL,
	distinguished_name TEXT NOT NULL,
	created_us         INTEGER NOT NULL,
	last_verified_us   INTEGER,
	UNIQUE (provider, subject)
) STRICT;
CREATE TABLE authldap_revalidation (
	user_id    INTEGER PRIMARY KEY CHECK (user_id > 0),
	required   INTEGER NOT NULL DEFAULT 0 CHECK (required IN (0, 1)),
	checked_us INTEGER NOT NULL DEFAULT 0
) STRICT;`}}}
}

// Identity is one row of authldap_identities.
type Identity struct {
	ID                int64
	UserID            int64
	Provider          string
	Subject           string
	DirectoryUsername string
	DistinguishedName string
	CreatedAt         time.Time
	LastVerifiedAt    time.Time // zero when never verified
}

const identityColumns = `id, user_id, provider, subject, directory_username, distinguished_name, created_us, last_verified_us`

func micros(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UnixMicro()
}

func fromMicros(v sql.NullInt64) time.Time {
	if !v.Valid {
		return time.Time{}
	}
	return time.UnixMicro(v.Int64).UTC()
}

type scanner interface{ Scan(dest ...any) error }

func scanIdentity(row scanner) (Identity, error) {
	var id Identity
	var created int64
	var verified sql.NullInt64
	err := row.Scan(&id.ID, &id.UserID, &id.Provider, &id.Subject, &id.DirectoryUsername, &id.DistinguishedName, &created, &verified)
	id.CreatedAt, id.LastVerifiedAt = time.UnixMicro(created).UTC(), fromMicros(verified)
	return id, err
}

// errNoIdentity is sql.ErrNoRows of the identity queries.
var errNoIdentity = errors.New("ldap: no identity")

func identityWhere(ctx context.Context, tx *store.Tx, where string, args ...any) (Identity, error) {
	id, err := scanIdentity(tx.QueryRowContext(ctx, `SELECT `+identityColumns+` FROM authldap_identities WHERE `+where, args...)) // #nosec G202 -- where is a constant of this package
	if errors.Is(err, sql.ErrNoRows) {
		return Identity{}, errNoIdentity
	}
	if err != nil {
		return Identity{}, fmt.Errorf("ldap: read identity: %w", err)
	}
	return id, nil
}

// identityOfTx returns the identity of an account or errNoIdentity.
func identityOfTx(ctx context.Context, tx *store.Tx, userID int64) (Identity, error) {
	return identityWhere(ctx, tx, `user_id = ?`, userID)
}

func identityBySubjectTx(ctx context.Context, tx *store.Tx, provider, subject string) (Identity, error) {
	return identityWhere(ctx, tx, `provider = ? AND subject = ?`, provider, subject)
}

// AccountOfTx returns the account bound to (provider, subject), the
// lookup of a directory sign-in, or fault.NotFound.
func AccountOfTx(ctx context.Context, tx *store.Tx, provider, subject string) (int64, error) {
	id, err := identityBySubjectTx(ctx, tx, provider, subject)
	if errors.Is(err, errNoIdentity) {
		return 0, fault.New(fault.NotFound, "")
	}
	return id.UserID, err
}

// insertIdentityTx stores a new identity; id 0 lets SQLite choose one.
// The uniqueness of (provider, subject) and of user_id is the table's.
func insertIdentityTx(ctx context.Context, tx *store.Tx, id Identity) (int64, error) {
	var rowID any
	if id.ID != 0 {
		rowID = id.ID
	}
	var out int64
	err := tx.QueryRowContext(ctx, `INSERT INTO authldap_identities (id, user_id, provider, subject, directory_username,
		distinguished_name, created_us, last_verified_us) VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`,
		rowID, id.UserID, id.Provider, id.Subject, id.DirectoryUsername, id.DistinguishedName, id.CreatedAt.UnixMicro(),
		micros(id.LastVerifiedAt)).Scan(&out)
	if err != nil {
		return 0, fmt.Errorf("ldap: insert identity: %w", err)
	}
	return out, nil
}

// ImportIdentityTx stores a migrated identity with its legacy id (E03).
func ImportIdentityTx(ctx context.Context, tx *store.Tx, id Identity) error {
	if id.ID <= 0 {
		return errors.New("ldap: imported identity needs its legacy id")
	}
	_, err := insertIdentityTx(ctx, tx, id)
	return err
}

// IdentitiesTx returns every identity by id (migration verification and
// the revalidation sweep).
func IdentitiesTx(ctx context.Context, tx *store.Tx) ([]Identity, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+identityColumns+` FROM authldap_identities ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("ldap: list identities: %w", err)
	}
	defer rows.Close()
	var out []Identity
	for rows.Next() {
		id, err := scanIdentity(rows)
		if err != nil {
			return nil, fmt.Errorf("ldap: list identities: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// RequireRevalidationTx marks an account: no access until a directory
// check succeeds (the migration of a Python revocation fence, E37).
func RequireRevalidationTx(ctx context.Context, tx *store.Tx, userID int64) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO authldap_revalidation (user_id, required, checked_us) VALUES (?, 1, 0)
		ON CONFLICT (user_id) DO UPDATE SET required = 1`, userID)
	if err != nil {
		return fmt.Errorf("ldap: require revalidation: %w", err)
	}
	return nil
}

// RevalidationTx returns the revalidation state of an account: whether a
// check is required and when the last one succeeded (zero for never).
func RevalidationTx(ctx context.Context, tx *store.Tx, userID int64) (required bool, checked time.Time, err error) {
	var us int64
	err = tx.QueryRowContext(ctx, `SELECT required, checked_us FROM authldap_revalidation WHERE user_id = ?`, userID).Scan(&required, &us)
	if errors.Is(err, sql.ErrNoRows) {
		return false, time.Time{}, nil
	}
	if err != nil {
		return false, time.Time{}, fmt.Errorf("ldap: read revalidation: %w", err)
	}
	if us != 0 {
		checked = time.UnixMicro(us).UTC()
	}
	return required, checked, nil
}

// checkedTx records a successful directory check and clears the
// requirement.
func checkedTx(ctx context.Context, tx *store.Tx, userID int64, at time.Time) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO authldap_revalidation (user_id, required, checked_us) VALUES (?, 0, ?)
		ON CONFLICT (user_id) DO UPDATE SET required = 0, checked_us = excluded.checked_us`, userID, at.UnixMicro())
	if err != nil {
		return fmt.Errorf("ldap: record check: %w", err)
	}
	return nil
}

// forgetTx drops the revalidation state of an account whose identity
// went away, so a later identity starts without an old check.
func forgetTx(ctx context.Context, tx *store.Tx, userID int64) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM authldap_revalidation WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("ldap: forget revalidation: %w", err)
	}
	return nil
}
