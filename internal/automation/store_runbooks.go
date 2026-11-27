package automation

import (
	"context"
	"database/sql"
	"encoding/json/jsontext"
	"errors"
	"fmt"

	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/store"
)

type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// ReadRunbooksTx returns the runbook library of a user in its order.
func ReadRunbooksTx(ctx context.Context, tx *store.Tx, userID int64) ([]Runbook, error) {
	return readRunbooks(ctx, tx, userID)
}

func readRunbooks(ctx context.Context, q querier, userID int64) ([]Runbook, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, name, stop_on_error FROM automation_runbooks WHERE user_id = ? ORDER BY seq`, userID)
	if err != nil {
		return nil, err
	}
	var books []Runbook
	index := map[string]int{}
	for rows.Next() {
		var b Runbook
		if err := rows.Scan(&b.ID, &b.Name, &b.StopOnError); err != nil {
			_ = rows.Close()
			return nil, err
		}
		index[b.ID] = len(books)
		books = append(books, b)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, err
	}
	steps, err := q.QueryContext(ctx, `SELECT runbook_id, name, command, timeout, sudo FROM automation_runbook_steps WHERE user_id = ? ORDER BY runbook_id, position`, userID)
	if err != nil {
		return nil, err
	}
	for steps.Next() {
		var id string
		var s Step
		if err := steps.Scan(&id, &s.Name, &s.Command, &s.Timeout, &s.Sudo); err != nil {
			_ = steps.Close()
			return nil, err
		}
		if i, ok := index[id]; ok {
			books[i].Steps = append(books[i].Steps, s)
		}
	}
	return books, errors.Join(steps.Err(), steps.Close())
}

// WriteRunbooksTx replaces the library of a user with books, in order.
// It does not check the limits: the service does for changes, and the
// migration keeps what the Python release stored.
func WriteRunbooksTx(ctx context.Context, tx *store.Tx, userID int64, books []Runbook) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM automation_runbooks WHERE user_id = ?`, userID); err != nil {
		return err
	}
	for i, b := range books {
		if _, err := tx.ExecContext(ctx, `INSERT INTO automation_runbooks (user_id, id, seq, name, stop_on_error) VALUES (?, ?, ?, ?, ?)`,
			userID, b.ID, i, b.Name, b.StopOnError); err != nil {
			return fmt.Errorf("automation: runbook %d: %w", i, err)
		}
		for j, s := range b.Steps {
			if _, err := tx.ExecContext(ctx, `INSERT INTO automation_runbook_steps (user_id, runbook_id, position, name, command, timeout, sudo) VALUES (?, ?, ?, ?, ?, ?, ?)`,
				userID, b.ID, j, s.Name, s.Command, s.Timeout, s.Sudo); err != nil {
				return fmt.Errorf("automation: runbook %d step %d: %w", i, j, err)
			}
		}
	}
	return nil
}

// libraryBytes is the size of automation.json as the Python release
// wrote it (json.dumps with indent 2), which its limit applies to.
func libraryBytes(books []Runbook) int {
	items := make([]jsontext.Value, len(books))
	for i, b := range books {
		items[i] = b.Value()
	}
	doc := pyjson.Object([]pyjson.Member{
		{Name: "version", Value: jsontext.Value("1")},
		{Name: "runbooks", Value: pyjson.Array(items)},
	})
	return len(pyDump(doc, dumpOptions{indent: 2}))
}

// saveRunbook is save_runbook: a runbook with an id replaces the
// existing one, which must exist, and moves to the end; a new one is
// appended. The library stays within MaxRunbooks and MaxStoreBytes.
func saveRunbook(books []Runbook, b Runbook, hadID bool) ([]Runbook, error) {
	found := false
	out := make([]Runbook, 0, len(books)+1)
	for _, item := range books {
		if item.ID == b.ID {
			found = true
			continue
		}
		out = append(out, item)
	}
	if hadID && !found {
		return nil, Fail("not_found")
	}
	out = append(out, b)
	if len(out) > MaxRunbooks || libraryBytes(out) > MaxStoreBytes {
		return nil, Fail("storage_limit")
	}
	return out, nil
}
