package accounts

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/session"
	"github.com/bifrost0x/webssh/internal/store"
)

// Schema is the account store. Times are microseconds since the Unix
// epoch in UTC; created_us is NULL for legacy accounts without a creation
// time. managed_by and the id floor have no Python column: the migration
// derives managed_by from the LDAP and GitHub identities and sets the
// floor above every legacy and quarantined id, so ids are never reused
// (migration specification 4.1).
func Schema() store.Schema {
	return store.Schema{Owner: "accounts", Migrations: []store.Migration{{Version: 1, SQL: `
CREATE TABLE accounts_users (
	id                      INTEGER PRIMARY KEY,
	username                TEXT NOT NULL UNIQUE,
	incarnation             TEXT NOT NULL,
	history_generation      TEXT NOT NULL,
	created_us              INTEGER,
	last_login_us           INTEGER,
	is_admin                INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0, 1)),
	is_locked               INTEGER NOT NULL DEFAULT 0 CHECK (is_locked IN (0, 1)),
	auth_generation         INTEGER NOT NULL DEFAULT 0,
	mfa_required            INTEGER NOT NULL DEFAULT 0 CHECK (mfa_required IN (0, 1)),
	mfa_failed_attempts     INTEGER NOT NULL DEFAULT 0,
	mfa_last_failed_us      INTEGER,
	step_up_failed_attempts INTEGER NOT NULL DEFAULT 0,
	step_up_last_failed_us  INTEGER,
	managed_by              TEXT NOT NULL DEFAULT '' CHECK (managed_by IN ('', 'ldap', 'github')),
	legacy_extra            TEXT NOT NULL DEFAULT '{}'
) STRICT;
CREATE TABLE accounts_id_floor (
	singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
	value     INTEGER NOT NULL
) STRICT;
INSERT INTO accounts_id_floor (singleton, value) VALUES (1, 0);
CREATE TABLE accounts_quarantine (
	path           TEXT PRIMARY KEY,
	former_user_id INTEGER NOT NULL,
	found_us       INTEGER NOT NULL
) STRICT;`}}}
}

// Service is the account service. It is safe for concurrent use.
type Service struct {
	DB          *store.DB
	Credentials Credentials
	Admins      Admins
	Audit       Auditor
	// Sessions ends the sessions and live resources of an account that is
	// locked, reset or deleted; Data removes a deleted account's rows after
	// Retain received their copy. They are set by the composition root.
	Sessions  Sessions
	Roles     RoleChanges
	Data      UserData
	Retain    Retainer
	Factors   Factors
	Recovery  RecoveryCodes
	LegacyDir LegacyUserDir
	Logger    *slog.Logger
	// Now replaces the clock in tests.
	Now func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

const columns = `id, username, incarnation, history_generation, created_us, last_login_us, is_admin, is_locked,
	auth_generation, mfa_required, managed_by`

type scanner interface{ Scan(...any) error }

func scan(row scanner) (Account, error) {
	var a Account
	var created, last sql.NullInt64
	var managed string
	if err := row.Scan(&a.ID, &a.Username, &a.Incarnation, &a.HistoryGeneration, &created, &last, &a.IsAdmin,
		&a.IsLocked, &a.AuthGeneration, &a.MFARequired, &managed); err != nil {
		return Account{}, err
	}
	a.Managed = Manager(managed)
	if created.Valid {
		a.CreatedAt = time.UnixMicro(created.Int64).UTC()
	}
	if last.Valid {
		a.LastLogin = time.UnixMicro(last.Int64).UTC()
	}
	return a, nil
}

var errNotFound = fault.New(fault.NotFound, "User not found")

func (s *Service) one(ctx context.Context, where string, arg any) (Account, error) {
	var a Account
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		a, err = scan(tx.QueryRowContext(ctx, `SELECT `+columns+` FROM accounts_users WHERE `+where, arg))
		return err
	})
	if errors.Is(err, sql.ErrNoRows) {
		return Account{}, errNotFound
	}
	if err != nil {
		return Account{}, fault.Wrap(fault.StorageError, err, "")
	}
	return a, nil
}

// Get returns an account by id.
func (s *Service) Get(ctx context.Context, id int64) (Account, error) {
	return s.one(ctx, `id = ?`, id)
}

// ByUsername returns the account with exactly this name.
func (s *Service) ByUsername(ctx context.Context, name string) (Account, error) {
	return s.one(ctx, `username = ?`, name)
}

// SignInStanding implements local.Accounts.
func (s *Service) SignInStanding(ctx context.Context, name string) (int64, bool, error) {
	a, err := s.ByUsername(ctx, name)
	if fault.Is(err, fault.NotFound) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return a.ID, !a.IsLocked && a.Managed == ManagedLocal, nil
}

// Standing implements session.Accounts.
func (s *Service) Standing(ctx context.Context, id int64) (session.Standing, error) {
	a, err := s.Get(ctx, id)
	if fault.Is(err, fault.NotFound) {
		return session.Standing{}, nil
	}
	if err != nil {
		return session.Standing{}, err
	}
	return session.Standing{Exists: true, Username: a.Username, IsAdmin: a.IsAdmin, Locked: a.IsLocked,
		Managed: a.Managed != ManagedLocal, Generation: a.AuthGeneration}, nil
}

// List returns every account by id.
func (s *Service) List(ctx context.Context) ([]Account, error) {
	var out []Account
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT `+columns+` FROM accounts_users ORDER BY id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			a, err := scan(rows)
			if err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fault.Wrap(fault.StorageError, err, "")
	}
	return out, nil
}

// RecordSignIn stores the time of a completed sign-in.
func (s *Service) RecordSignIn(ctx context.Context, id int64) error {
	err := s.DB.Write(ctx, func(tx *store.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE accounts_users SET last_login_us = ? WHERE id = ?`, s.now().UnixMicro(), id)
		return err
	})
	if err != nil {
		return fault.Wrap(fault.StorageError, err, "")
	}
	return nil
}

// PasswordChangedTx raises the account's auth_generation after a password
// change, which ends every credential issued before (sessions, pending
// sign-ins, step-up grants), and returns the new generation. A legacy
// account whose history namespace came from its password hash (no
// creation time) starts a fresh history, as a password change did in the
// Python release.
func (s *Service) PasswordChangedTx(ctx context.Context, tx *store.Tx, id int64, newHash string) (int64, error) {
	var gen int64
	err := tx.QueryRowContext(ctx, `UPDATE accounts_users SET auth_generation = auth_generation + 1,
		history_generation = CASE WHEN history_generation <> incarnation THEN ? ELSE history_generation END
		WHERE id = ? RETURNING auth_generation`, newHash, id).Scan(&gen)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, errNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("accounts: raise generation: %w", err)
	}
	return gen, nil
}

// SetMFARequiredTx records whether the account requires a second factor
// (users.mfa_enabled); the factor packages call it.
func (s *Service) SetMFARequiredTx(ctx context.Context, tx *store.Tx, id int64, required bool) error {
	res, err := tx.ExecContext(ctx, `UPDATE accounts_users SET mfa_required = ? WHERE id = ?`, required, id)
	if err != nil {
		return fmt.Errorf("accounts: set mfa_required: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

// MFARequiredTx reads whether the account requires a second factor inside
// the caller's transaction, so that a factor change and the flag it
// depends on are read and written together.
func (s *Service) MFARequiredTx(ctx context.Context, tx *store.Tx, id int64) (bool, error) {
	var required bool
	err := tx.QueryRowContext(ctx, `SELECT mfa_required FROM accounts_users WHERE id = ?`, id).Scan(&required)
	if errors.Is(err, sql.ErrNoRows) {
		return false, errNotFound
	}
	if err != nil {
		return false, fmt.Errorf("accounts: read mfa_required: %w", err)
	}
	return required, nil
}

// RaiseIDFloorTx makes every later id larger than floor; the migration
// calls it with the largest legacy and quarantined id.
func (s *Service) RaiseIDFloorTx(ctx context.Context, tx *store.Tx, floor int64) error {
	_, err := tx.ExecContext(ctx, `UPDATE accounts_id_floor SET value = max(value, ?) WHERE singleton = 1`, floor)
	if err != nil {
		return fmt.Errorf("accounts: raise id floor: %w", err)
	}
	return nil
}
