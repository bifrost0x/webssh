package automation

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"slices"

	"github.com/bifrost0x/webssh/internal/store"
)

type storedRun struct {
	seq int64
	run Run
}

// readRuns returns the history of a user, the newest first. A record
// that does not validate makes the history unavailable, as a damaged
// automation-runs.json did.
func readRuns(ctx context.Context, q querier, userID int64) ([]storedRun, error) {
	rows, err := q.QueryContext(ctx, `SELECT seq, document FROM automation_runs WHERE user_id = ? ORDER BY seq DESC`, userID)
	if err != nil {
		return nil, err
	}
	var out []storedRun
	for rows.Next() {
		var seq int64
		var doc string
		if err := rows.Scan(&seq, &doc); err != nil {
			_ = rows.Close()
			return nil, err
		}
		r, err := ParseRun(jsontext.Value(doc))
		if err != nil {
			_ = rows.Close()
			return nil, Fail("storage_unavailable")
		}
		out = append(out, storedRun{seq: seq, run: r})
	}
	return out, errors.Join(rows.Err(), rows.Close())
}

// runRow is a history row without its document.
type runRow struct {
	id   string
	seq  int64
	size int
}

func readRows(ctx context.Context, q querier, userID int64) ([]runRow, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, seq, py_size FROM automation_runs WHERE user_id = ? ORDER BY seq DESC`, userID)
	if err != nil {
		return nil, err
	}
	var out []runRow
	for rows.Next() {
		var r runRow
		if err := rows.Scan(&r.id, &r.seq, &r.size); err != nil {
			_ = rows.Close()
			return nil, err
		}
		out = append(out, r)
	}
	return out, errors.Join(rows.Err(), rows.Close())
}

// ExportRunsTx returns the stored history of a user, the newest first
// (migration verification).
func ExportRunsTx(ctx context.Context, tx *store.Tx, userID int64) ([]Run, error) {
	stored, err := readRuns(ctx, tx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]Run, len(stored))
	for i, s := range stored {
		out[i] = s.run
	}
	return out, nil
}

// ImportRunsTx stores the history of a user, newest first, as the
// migration read it. It replaces whatever the user had.
func ImportRunsTx(ctx context.Context, tx *store.Tx, userID int64, runs []Run) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM automation_runs WHERE user_id = ?`, userID); err != nil {
		return err
	}
	for i := range runs {
		if err := upsertRun(ctx, tx, userID, int64(len(runs)-i), &runs[i]); err != nil {
			return err
		}
	}
	return nil
}

func upsertRun(ctx context.Context, tx *store.Tx, userID, seq int64, r *Run) error {
	doc := r.Value()
	_, err := tx.ExecContext(ctx, `INSERT INTO automation_runs (user_id, id, seq, document, py_size) VALUES (?, ?, ?, ?, ?)
ON CONFLICT (user_id, id) DO UPDATE SET seq = excluded.seq, document = excluded.document, py_size = excluded.py_size`,
		userID, r.ID, seq, string(doc), runBytes(doc))
	if err != nil {
		return fmt.Errorf("automation: store run: %w", err)
	}
	return nil
}

// runBytes is the size of a record inside the indented history file.
func runBytes(doc jsontext.Value) int { return len(pyDumpAt(doc, dumpOptions{indent: 2}, 2)) }

// Framing of automation-runs.json written with indent 2: the members
// before the list, the separator and indentation before each record,
// and the end.
const (
	historyHead  = len("{\n  \"version\": 1,\n  \"runs\": [")
	historyItem  = len(",\n    ")
	historyTail  = len("\n  ]\n}")
	historyEmpty = len("{\n  \"version\": 1,\n  \"runs\": []\n}")
)

// historySize is document_bytes of a history with records of the sizes.
func historySize(sizes []int) int {
	if len(sizes) == 0 {
		return historyEmpty
	}
	n := historyHead + historyTail - 1 // the first record has no comma
	for _, s := range sizes {
		n += historyItem + s
	}
	return n
}

// historyBytes is the size of automation-runs.json for the runs.
func historyBytes(runs []Run) int {
	sizes := make([]int, len(runs))
	for i := range runs {
		sizes[i] = runBytes(runs[i].Value())
	}
	return historySize(sizes)
}

// keep is how many of the newest records stay within MaxStoreBytes; the
// newest always stays (_trim_history).
func keep(sizes []int) int {
	n := len(sizes)
	for n > 1 && historySize(sizes[:n]) > MaxStoreBytes {
		n--
	}
	return n
}

// trim drops the oldest runs while the history is above MaxStoreBytes.
func trim(runs []Run) []Run {
	sizes := make([]int, len(runs))
	for i := range runs {
		sizes[i] = runBytes(runs[i].Value())
	}
	return runs[:keep(sizes)]
}

// persistRun is _persist: the record goes to the front of the history,
// which keeps MaxRuns records within MaxStoreBytes. Only the record is
// written; older rows keep their documents.
func persistRun(ctx context.Context, tx *store.Tx, userID int64, r Run) error {
	rows, err := readRows(ctx, tx, userID)
	if err != nil {
		return err
	}
	doc := r.Value()
	list := []runRow{{id: r.ID, size: runBytes(doc)}}
	var top int64
	for _, row := range rows {
		top = max(top, row.seq)
		if row.id != r.ID {
			list = append(list, row)
		}
	}
	if len(list) > MaxRuns {
		list = list[:MaxRuns]
	}
	sizes := make([]int, len(list))
	for i, row := range list {
		sizes[i] = row.size
	}
	list = list[:keep(sizes)]
	if err := dropRows(ctx, tx, userID, rows, list); err != nil {
		return err
	}
	seq := top + 1
	if len(rows) > 0 && rows[0].id == r.ID {
		seq = rows[0].seq
	}
	return upsertRun(ctx, tx, userID, seq, &r)
}

// dropRows deletes the rows that are no longer listed.
func dropRows(ctx context.Context, tx *store.Tx, userID int64, before, after []runRow) error {
	for _, row := range before {
		if !slices.ContainsFunc(after, func(a runRow) bool { return a.id == row.id }) {
			if _, err := tx.ExecContext(ctx, `DELETE FROM automation_runs WHERE user_id = ? AND id = ?`, userID, row.id); err != nil {
				return err
			}
		}
	}
	return nil
}

// recoverRun applies the load-time rule of history(): a record that is
// not finished and not running in this process is unknown, its open
// steps interrupted. It reports whether r changed.
func recoverRun(r *Run) bool {
	if terminal(r.Status) {
		return false
	}
	r.Status = StatusUnknown
	for i := range r.Targets {
		t := &r.Targets[i]
		if !terminal(t.Status) {
			t.Status = StatusUnknown
		}
		for j := range t.Steps {
			s := &t.Steps[j]
			if !terminal(s.Status) {
				s.Status = StatusUnknown
				if s.Detailed {
					s.Reason = new("run_interrupted")
				}
			}
		}
	}
	return true
}

// storeRecovered writes the recovered records in place, then trims.
func storeRecovered(ctx context.Context, tx *store.Tx, userID int64, stored []storedRun, recovered []Run) error {
	for i := range recovered {
		if err := upsertRun(ctx, tx, userID, stored[i].seq, &recovered[i]); err != nil {
			return err
		}
	}
	rows, err := readRows(ctx, tx, userID)
	if err != nil {
		return err
	}
	sizes := make([]int, len(rows))
	for i, row := range rows {
		sizes[i] = row.size
	}
	return dropRows(ctx, tx, userID, rows, rows[:keep(sizes)])
}

// deleteRuns removes finished runs: ids nil removes every run that is
// not active. It returns the number removed.
func deleteRuns(ctx context.Context, tx *store.Tx, userID int64, ids []string, active func(string) bool) (int, error) {
	rows, err := readRows(ctx, tx, userID)
	if err != nil {
		return 0, err
	}
	var kept []runRow
	for _, row := range rows {
		if active(row.id) || (ids != nil && !slices.Contains(ids, row.id)) {
			kept = append(kept, row)
		}
	}
	removed := len(rows) - len(kept)
	if ids != nil && removed != len(dedupe(ids)) {
		return 0, Fail("not_found")
	}
	return removed, dropRows(ctx, tx, userID, rows, kept)
}

func dedupe(ids []string) []string {
	out := slices.Clone(ids)
	slices.Sort(out)
	return slices.Compact(out)
}
