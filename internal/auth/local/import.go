package local

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/bifrost0x/webssh/internal/store"
)

// ErrLegacyHash marks a Python password hash that is not a bcrypt hash
// this package can verify; the migration stops on it (entity E02).
var ErrLegacyHash = errors.New("local: legacy password hash is not bcrypt")

// ImportTx stores the bcrypt hash of a Python account unchanged, inside
// the migration's transaction (entity E02). The first successful sign-in
// replaces it with Argon2id (D-12). Directory- and GitHub-managed
// accounts keep their random hash; they never sign in with it.
func ImportTx(ctx context.Context, tx *store.Tx, userID int64, hash string, at time.Time) error {
	if userID <= 0 || !validBcrypt(hash) {
		return fmt.Errorf("%w: user %d", ErrLegacyHash, userID)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO authlocal_passwords (user_id, algorithm, hash, updated_us) VALUES (?, ?, ?, ?)`,
		userID, AlgorithmBcrypt, hash, at.UnixMicro()); err != nil {
		return fmt.Errorf("local: import password of user %d: %w", userID, err)
	}
	return nil
}

// StoredTx returns the algorithm and hash stored for userID, for the
// migration's verification.
func StoredTx(ctx context.Context, tx *store.Tx, userID int64) (algorithm, hash string, found bool, err error) {
	err = tx.QueryRowContext(ctx, `SELECT algorithm, hash FROM authlocal_passwords WHERE user_id = ?`, userID).Scan(&algorithm, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, fmt.Errorf("local: read password of user %d: %w", userID, err)
	}
	return algorithm, hash, true, nil
}
