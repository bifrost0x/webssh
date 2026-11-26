package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// ErrCorrupt reports a database that failed an integrity check. A damaged
// Go database is never replaced automatically (state S7 of the migration
// specification).
var ErrCorrupt = errors.New("store: database integrity check failed")

// maxProblems bounds the problems a check reports.
const maxProblems = 20

// QuickCheck runs PRAGMA quick_check, the check of every start: it finds
// damaged pages and records but not every index inconsistency.
func (db *DB) QuickCheck(ctx context.Context) error {
	return db.check(ctx, fmt.Sprintf("PRAGMA quick_check(%d)", maxProblems))
}

// IntegrityCheck runs PRAGMA integrity_check and PRAGMA foreign_key_check,
// the full check of a migrated database before activation (migration
// specification, 5.2 step 8).
func (db *DB) IntegrityCheck(ctx context.Context) error {
	if err := db.check(ctx, fmt.Sprintf("PRAGMA integrity_check(%d)", maxProblems)); err != nil {
		return err
	}
	return db.Read(ctx, func(tx *Tx) error {
		rows, err := tx.QueryContext(ctx, "PRAGMA foreign_key_check")
		if err != nil {
			return fmt.Errorf("store: foreign_key_check: %w", err)
		}
		defer rows.Close()
		var problems []string
		for rows.Next() && len(problems) < maxProblems {
			var table, parent string
			var rowid, fkid any
			if err := rows.Scan(&table, &rowid, &parent, &fkid); err != nil {
				return fmt.Errorf("store: foreign_key_check: %w", err)
			}
			problems = append(problems, fmt.Sprintf("%s row %v references a missing %s row", table, rowid, parent))
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("store: foreign_key_check: %w", err)
		}
		if len(problems) > 0 {
			return fmt.Errorf("%w: %s", ErrCorrupt, strings.Join(problems, "; "))
		}
		return nil
	})
}

// check runs a check pragma, which answers "ok" or a list of problems.
func (db *DB) check(ctx context.Context, pragma string) error {
	return db.Read(ctx, func(tx *Tx) error {
		rows, err := tx.QueryContext(ctx, pragma)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrCorrupt, err)
		}
		defer rows.Close()
		var lines []string
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				return fmt.Errorf("%w: %w", ErrCorrupt, err)
			}
			lines = append(lines, line)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("%w: %w", ErrCorrupt, err)
		}
		if len(lines) != 1 || lines[0] != "ok" {
			return fmt.Errorf("%w: %s", ErrCorrupt, strings.Join(lines, "; "))
		}
		return nil
	})
}
