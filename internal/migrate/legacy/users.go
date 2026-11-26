package legacy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// User is one row of the users table.
type User struct {
	ID             int64
	Username       string
	PasswordHash   string
	CreatedAt      sql.NullString // naive UTC text as stored
	IsAdmin        bool
	IsLocked       bool
	AuthGeneration int64
	MFAEnabled     bool
}

// ErrNoIncarnation reports an account whose created_at is NULL. Python
// 3.3.x signs such an account in, but its saved passwords, automation
// vault and schedules cannot be used (incarnation() fails); the
// migration keeps the records and reports them (specification 4.2).
var ErrNoIncarnation = errors.New("legacy: account has no incarnation (created_at is NULL)")

// Incarnation is the account incarnation that named credentials and the
// automation vault bind to (app/automation_store.py incarnation).
func (u User) Incarnation() (string, error) {
	if !u.CreatedAt.Valid {
		return "", fmt.Errorf("%w: user %d", ErrNoIncarnation, u.ID)
	}
	return incarnationOf(u.CreatedAt.String)
}

// Users returns all accounts ordered by id. Columns an older database
// lacks get the values app/models.py ensure_user_columns gives existing
// rows; without is_admin only the account with the lowest id is an
// administrator, as Python's first start of the new schema decides.
func (s *Source) Users(ctx context.Context) ([]User, error) {
	// The select list holds only the constant column names below, or
	// constant defaults where a column is absent; nothing from the data.
	query := "SELECT " + s.schema.userSelect("id", "username", "password_hash", "created_at", // #nosec G202 -- constant identifiers and literals
		"is_admin", "is_locked", "auth_generation", "mfa_enabled") + " FROM users ORDER BY id"
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("legacy: read users: %w", err)
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.CreatedAt,
			&u.IsAdmin, &u.IsLocked, &u.AuthGeneration, &u.MFAEnabled); err != nil {
			return nil, fmt.Errorf("legacy: read users: %w", err)
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("legacy: read users: %w", err)
	}
	if !s.schema.HasColumn("users", "is_admin") && len(users) > 0 {
		users[0].IsAdmin = true
	}
	return users, nil
}

// user returns one account.
func (s *Source) user(ctx context.Context, id int64) (User, error) {
	users, err := s.Users(ctx)
	if err != nil {
		return User{}, err
	}
	for _, u := range users {
		if u.ID == id {
			return u, nil
		}
	}
	return User{}, fmt.Errorf("%w: user %d", ErrNotFound, id)
}

// bcryptMaxPassword is the input limit of bcrypt. The Python release
// rejects longer passwords before hashing (app/auth.py
// password_exceeds_bcrypt_limit), so no stored hash covers a longer one.
const bcryptMaxPassword = 72

// ErrPasswordMismatch reports a password that does not match its hash.
var ErrPasswordMismatch = errors.New("legacy: password does not match")

// VerifyPassword checks password against a stored bcrypt hash
// ("$2b$<cost>$..."). Hashes of other formats are rejected.
func VerifyPassword(hash, password string) error {
	if !strings.HasPrefix(hash, "$2b$") && !strings.HasPrefix(hash, "$2a$") && !strings.HasPrefix(hash, "$2y$") {
		return errors.New("legacy: password hash is not bcrypt")
	}
	if len(password) > bcryptMaxPassword {
		return ErrPasswordMismatch
	}
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return ErrPasswordMismatch
	}
	if err != nil {
		return fmt.Errorf("legacy: invalid bcrypt hash: %w", err)
	}
	return nil
}

// BcryptCost returns the cost factor of a stored hash.
func BcryptCost(hash string) (int, error) {
	return bcrypt.Cost([]byte(hash))
}

// ConnectionHistoryScope returns the browser-storage namespace of
// app/browser_identity.py, which the browser keeps the connection history
// under. A different value hides the history after the upgrade (D-10).
func (s *Source) ConnectionHistoryScope(u User) (string, error) {
	generation := u.PasswordHash // Python's fallback for a null created_at
	if u.CreatedAt.Valid {
		var err error
		if generation, err = u.Incarnation(); err != nil {
			return "", err
		}
	}
	material := strings.Join([]string{"webssh-connection-history-v1", strconv.FormatInt(u.ID, 10), u.Username, generation}, "\x00")
	mac := hmac.New(sha256.New, []byte(s.secret))
	mac.Write([]byte(material))
	return hex.EncodeToString(mac.Sum(nil)), nil
}
