package hostops

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/store"
)

// Notes keeps the notes of every user (D-11). This release serves the
// note without a host, the notepad of the workspace.
type Notes struct {
	DB *store.DB
}

var errNoteTooLarge = fault.New(fault.TooLarge, "Notepad content too large (max 100000 characters)")

// Note returns the note of owner without a host, "" when there is none.
func (n *Notes) Note(ctx context.Context, owner int64) (string, error) {
	var body string
	err := n.DB.Read(ctx, func(tx *store.Tx) error {
		err := tx.QueryRowContext(ctx, `SELECT body FROM hostops_notes WHERE user_id = ? AND profile_id IS NULL`, owner).Scan(&body)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	})
	if err != nil {
		return "", fault.Wrap(fault.StorageError, err, "Failed to load notepad")
	}
	return body, nil
}

// SaveNote replaces the note of owner without a host. It returns only
// after the note is stored; an empty note removes it.
func (n *Notes) SaveNote(ctx context.Context, owner int64, text string) (string, error) {
	if utf8.RuneCountInString(text) > protocol.MaxNoteRunes {
		return "", errNoteTooLarge
	}
	err := n.DB.Write(ctx, func(tx *store.Tx) error {
		if text == "" {
			_, err := tx.ExecContext(ctx, `DELETE FROM hostops_notes WHERE user_id = ? AND profile_id IS NULL`, owner)
			return err
		}
		res, err := tx.ExecContext(ctx, `UPDATE hostops_notes SET body = ?, revision = revision + 1
WHERE user_id = ? AND profile_id IS NULL`, text, owner)
		if err != nil {
			return err
		}
		if changed, err := res.RowsAffected(); err != nil || changed > 0 {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO hostops_notes (user_id, profile_id, body, revision) VALUES (?, NULL, ?, 1)`, owner, text)
		return err
	})
	if err != nil {
		return "", fault.Wrap(fault.StorageError, err, "Failed to save notepad")
	}
	return text, nil
}

// ImportNote stores one legacy note in the migration's transaction: the
// notepad of settings.json with profileID "" (an empty notepad is not
// stored), or the notes of a host context with its revision.
func ImportNote(ctx context.Context, tx *store.Tx, owner int64, profileID, body string, revision int64) error {
	if body == "" {
		return nil
	}
	if revision < 0 {
		return fmt.Errorf("hostops: note revision %d is negative", revision)
	}
	var profile any
	if profileID != "" {
		profile = profileID
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO hostops_notes (user_id, profile_id, body, revision) VALUES (?, ?, ?, ?)`,
		owner, profile, body, revision); err != nil {
		return fmt.Errorf("hostops: import note: %w", err)
	}
	return nil
}
