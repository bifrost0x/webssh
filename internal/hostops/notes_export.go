package hostops

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/bifrost0x/webssh/internal/store"
)

// NoteTx returns the note of owner for profileID ("" for the note
// without a host) and its revision, for the migration's verification.
// found is false when there is none.
func NoteTx(ctx context.Context, tx *store.Tx, owner int64, profileID string) (body string, revision int64, found bool, err error) {
	q := `SELECT body, revision FROM hostops_notes WHERE user_id = ? AND profile_id = ?`
	args := []any{owner, profileID}
	if profileID == "" {
		q, args = `SELECT body, revision FROM hostops_notes WHERE user_id = ? AND profile_id IS NULL`, []any{owner}
	}
	err = tx.QueryRowContext(ctx, q, args...).Scan(&body, &revision)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, false, nil
	}
	if err != nil {
		return "", 0, false, fmt.Errorf("hostops: read note: %w", err)
	}
	return body, revision, true, nil
}
