package local

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
)

// MinPasswordRunes is MIN_PASSWORD_LENGTH, counted in code points as in
// the Python release.
const MinPasswordRunes = 8

// Accounts finds the account behind a submitted name (provided by
// internal/accounts). The name is compared exactly, as the Python
// release's sign-in does. userID is 0 when no account has the name;
// usable is false for locked accounts and for accounts managed by a
// directory or GitHub, which never sign in with a local password.
type Accounts interface {
	SignInStanding(ctx context.Context, username string) (userID int64, usable bool, err error)
}

// Schema is the password table. The Python bcrypt hashes are copied
// into it unchanged by the migration (entity E02).
func Schema() store.Schema {
	return store.Schema{Owner: "authlocal", Migrations: []store.Migration{{Version: 1, SQL: `
CREATE TABLE authlocal_passwords (
	user_id    INTEGER PRIMARY KEY,
	algorithm  TEXT NOT NULL CHECK (algorithm IN ('argon2id', 'bcrypt')),
	hash       TEXT NOT NULL,
	updated_us INTEGER NOT NULL
) STRICT;`}}}
}

// Provider is the local password provider of the sign-in registry.
type Provider struct {
	DB       *store.DB
	Accounts Accounts
	Hasher   *Hasher
	Logger   *slog.Logger
	Now      func() time.Time
}

// Name is the method name recorded in sessions and the audit log.
func (*Provider) Name() string { return "password" }

func (p *Provider) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Provider) logger() *slog.Logger {
	if p.Logger != nil {
		return p.Logger
	}
	return slog.Default()
}

var errFailed = fault.New(fault.AuthFailed, "Invalid username or password")

// stored is one password row.
type stored struct {
	algorithm, hash string
}

func (p *Provider) read(ctx context.Context, userID int64) (stored, bool, error) {
	var s stored
	err := p.DB.Read(ctx, func(tx *store.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT algorithm, hash FROM authlocal_passwords WHERE user_id = ?`, userID).Scan(&s.algorithm, &s.hash)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return stored{}, false, nil
	}
	if err != nil {
		return stored{}, false, fault.Wrap(fault.StorageError, err, "")
	}
	return s, true, nil
}

// Authenticate checks a name and password. Every wrong combination,
// including unknown, locked and directory-managed accounts, fails with the
// same fault.AuthFailed and costs the same time (failed).
// After a successful sign-in with a bcrypt hash or weaker Argon2id
// parameters the hash is replaced (D-12); a failed rehash is logged and
// does not fail the sign-in.
func (p *Provider) Authenticate(ctx context.Context, username, secret string) (int64, error) {
	if len(secret) > MaxPasswordBytes || !utf8.ValidString(secret) {
		return 0, errFailed
	}
	id, usable, err := p.Accounts.SignInStanding(ctx, username)
	if err != nil {
		return 0, err
	}
	if id == 0 {
		return 0, p.failed(ctx, secret, "")
	}
	row, found, err := p.read(ctx, id)
	if err != nil {
		return 0, err
	}
	if !found {
		return 0, p.failed(ctx, secret, "")
	}
	ok, rehash, err := p.Hasher.Verify(ctx, row.algorithm, row.hash, secret)
	if err != nil {
		if errors.Is(err, ErrFormat) {
			p.logger().WarnContext(ctx, "stored password hash is unusable", "user_id", id)
			return 0, p.failed(ctx, secret, "")
		}
		return 0, fault.Wrap(fault.Unavailable, err, "")
	}
	if !ok || !usable {
		return 0, p.failed(ctx, secret, row.algorithm)
	}
	if rehash {
		p.rehash(ctx, id, row, secret)
	}
	return id, nil
}

// failed spends what the failed sign-in of any other name costs, after
// spent (the algorithm already verified, "" for none): an Argon2id
// verification and, while bcrypt hashes remain, a bcrypt verification.
// So the answer time shows neither whether a name exists nor whether its
// hash was already migrated to Argon2id.
func (p *Provider) failed(ctx context.Context, secret, spent string) error {
	if spent != AlgorithmArgon2id {
		p.Hasher.SpendDummy(ctx, secret, AlgorithmArgon2id)
	}
	if spent != AlgorithmBcrypt && p.legacyHashes(ctx) {
		p.Hasher.SpendDummy(ctx, secret, AlgorithmBcrypt)
	}
	return errFailed
}

// legacyHashes reports whether any bcrypt hash is left; a failed read
// counts as yes, the slower dummy.
func (p *Provider) legacyHashes(ctx context.Context) bool {
	var n int
	err := p.DB.Read(ctx, func(tx *store.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM (SELECT 1 FROM authlocal_passwords WHERE algorithm = 'bcrypt' LIMIT 1)`).Scan(&n)
	})
	return err != nil || n > 0
}

// rehash replaces row with an Argon2id hash if the row is still the one
// that was verified.
func (p *Provider) rehash(ctx context.Context, id int64, old stored, secret string) {
	fresh, err := p.Hasher.Hash(ctx, secret)
	if err == nil {
		err = p.DB.Write(ctx, func(tx *store.Tx) error {
			_, err := tx.ExecContext(ctx, `UPDATE authlocal_passwords SET algorithm = ?, hash = ?, updated_us = ?
				WHERE user_id = ? AND algorithm = ? AND hash = ?`, AlgorithmArgon2id, fresh, p.now().UnixMicro(), id, old.algorithm, old.hash)
			return err
		})
	}
	if err != nil {
		p.logger().WarnContext(ctx, "password rehash failed", "user_id", id, "error", err)
	}
}

// Matches reports whether password is the account's current password,
// without rehashing (change-password and step-up use it).
func (p *Provider) Matches(ctx context.Context, userID int64, password string) (bool, error) {
	if len(password) > MaxPasswordBytes || !utf8.ValidString(password) {
		return false, nil
	}
	row, found, err := p.read(ctx, userID)
	if err != nil || !found {
		if !found && err == nil {
			p.Hasher.VerifyDummy(ctx, password, p.legacyHashes(ctx))
		}
		return false, err
	}
	ok, _, err := p.Hasher.Verify(ctx, row.algorithm, row.hash, password)
	if errors.Is(err, ErrFormat) {
		return false, nil
	}
	if err != nil {
		return false, fault.Wrap(fault.Unavailable, err, "")
	}
	return ok, nil
}

// Hash returns the stored form of a new password; ValidateNew must have
// accepted it.
func (p *Provider) Hash(ctx context.Context, password string) (string, error) {
	h, err := p.Hasher.Hash(ctx, password)
	if err != nil {
		return "", fault.Wrap(fault.Unavailable, err, "")
	}
	return h, nil
}

// StoreTx writes the Argon2id hash for userID inside a caller's
// transaction (account creation and password change are one write).
func (p *Provider) StoreTx(ctx context.Context, tx *store.Tx, userID int64, hash string) error {
	if _, _, _, err := parseArgon2(hash); err != nil {
		return fmt.Errorf("local: refuse to store %w", err)
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO authlocal_passwords (user_id, algorithm, hash, updated_us) VALUES (?, ?, ?, ?)
		ON CONFLICT (user_id) DO UPDATE SET algorithm = excluded.algorithm, hash = excluded.hash, updated_us = excluded.updated_us`,
		userID, AlgorithmArgon2id, hash, p.now().UnixMicro())
	if err != nil {
		return fmt.Errorf("local: store password: %w", err)
	}
	return nil
}

// ValidateNew returns the reason a new password is refused, or "". The
// texts are those of the Python release; the byte limit is D-12's.
func ValidateNew(password string) string {
	if utf8.RuneCountInString(password) < MinPasswordRunes {
		return "Password must be at least 8 characters"
	}
	if len(password) > MaxPasswordBytes || !utf8.ValidString(password) {
		return "Password must not exceed 1024 bytes when encoded as UTF-8"
	}
	return ""
}

// ValidateNew is the package function as a method, for consumers that
// declare it in an interface (internal/accounts).
func (*Provider) ValidateNew(password string) string { return ValidateNew(password) }
