package automation

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"slices"

	"github.com/bifrost0x/webssh/internal/pyjson"
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
	_, err := tx.ExecContext(ctx, `INSERT INTO automation_runs (user_id, id, seq, document) VALUES (?, ?, ?, ?)
ON CONFLICT (user_id, id) DO UPDATE SET seq = excluded.seq, document = excluded.document`, userID, r.ID, seq, string(r.Value()))
	if err != nil {
		return fmt.Errorf("automation: store run: %w", err)
	}
	return nil
}

// historyBytes is the size of automation-runs.json as the Python release
// wrote it (document_bytes), which the trimming rule applies to.
func historyBytes(runs []Run) int {
	items := make([]jsontext.Value, len(runs))
	for i := range runs {
		items[i] = runs[i].Value()
	}
	doc := pyjson.Object([]pyjson.Member{
		{Name: "version", Value: jsontext.Value("1")},
		{Name: "runs", Value: pyjson.Array(items)},
	})
	return len(pyDump(doc, dumpOptions{indent: 2}))
}

// trim drops the oldest runs while the history is above MaxStoreBytes;
// the newest run is never dropped (_trim_history).
func trim(runs []Run) []Run {
	for len(runs) > 1 && historyBytes(runs) > MaxStoreBytes {
		runs = runs[:len(runs)-1]
	}
	return runs
}

// rewrite stores runs (newest first) as the user's whole history: rows
// that are no longer listed go, the others keep or get their order.
func rewrite(ctx context.Context, tx *store.Tx, userID int64, before []storedRun, runs []Run) error {
	keep := map[string]bool{}
	for _, r := range runs {
		keep[r.ID] = true
	}
	for _, s := range before {
		if !keep[s.run.ID] {
			if _, err := tx.ExecContext(ctx, `DELETE FROM automation_runs WHERE user_id = ? AND id = ?`, userID, s.run.ID); err != nil {
				return err
			}
		}
	}
	var top int64
	if len(before) > 0 {
		top = before[0].seq
	}
	// Renumbering from the top keeps the unique order without a gap
	// check; at most MaxRuns rows move.
	if _, err := tx.ExecContext(ctx, `UPDATE automation_runs SET seq = -seq - 1 WHERE user_id = ?`, userID); err != nil {
		return err
	}
	for i := range runs {
		if err := upsertRun(ctx, tx, userID, top+int64(len(runs)-i), &runs[i]); err != nil {
			return err
		}
	}
	return nil
}

// persistRun is _persist: the record goes to the front of the history,
// which keeps MaxRuns records within MaxStoreBytes.
func persistRun(ctx context.Context, tx *store.Tx, userID int64, r Run) error {
	before, err := readRuns(ctx, tx, userID)
	if err != nil {
		return err
	}
	runs := []Run{r}
	for _, s := range before {
		if s.run.ID != r.ID {
			runs = append(runs, s.run)
		}
	}
	if len(runs) > MaxRuns {
		runs = runs[:MaxRuns]
	}
	return rewrite(ctx, tx, userID, before, trim(runs))
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
					s.Reason = ptr("run_interrupted")
				}
			}
		}
	}
	return true
}

// deleteRuns removes finished runs: ids nil removes every run that is
// not active. It returns the number removed.
func deleteRuns(ctx context.Context, tx *store.Tx, userID int64, ids []string, active func(string) bool) (int, error) {
	before, err := readRuns(ctx, tx, userID)
	if err != nil {
		return 0, err
	}
	var kept []Run
	for _, s := range before {
		if active(s.run.ID) || (ids != nil && !slices.Contains(ids, s.run.ID)) {
			kept = append(kept, s.run)
		}
	}
	removed := len(before) - len(kept)
	if ids != nil && removed != len(dedupe(ids)) {
		return 0, Fail("not_found")
	}
	if removed == 0 {
		return 0, nil
	}
	return removed, rewrite(ctx, tx, userID, before, trim(kept))
}

func dedupe(ids []string) []string {
	out := slices.Clone(ids)
	slices.Sort(out)
	return slices.Compact(out)
}
