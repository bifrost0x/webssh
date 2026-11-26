package jobs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bifrost0x/webssh/internal/store"
)

// Record is the durable state of one job. A run is claimed (Running+1,
// LastRun) before its function starts, so a run never starts twice for
// one claim: after a crash the claim is found at the next start and the
// run counts as interrupted instead of being repeated.
type Record struct {
	Name    string
	LastRun time.Time // start of the last run; zero when it never ran
	LastEnd time.Time // end of the last run that ended
	LastErr bool      // the last run ended with an error or was interrupted
	Pending int       // on-demand runs requested and not started
	Running int       // runs claimed and not ended
}

// Store keeps the records across restarts. Save replaces the record of
// one job. The registry calls Save for one job at a time, in order.
type Store interface {
	Load(ctx context.Context) ([]Record, error)
	Save(ctx context.Context, r Record) error
}

// Owner is the schema owner of the job state.
const Owner = "jobs"

const stateTableSQL = `CREATE TABLE jobs_state (
	name TEXT PRIMARY KEY CHECK (length(name) BETWEEN 1 AND 128),
	last_run INTEGER NOT NULL DEFAULT 0,
	last_end INTEGER NOT NULL DEFAULT 0,
	last_error INTEGER NOT NULL DEFAULT 0 CHECK (last_error IN (0, 1)),
	pending INTEGER NOT NULL DEFAULT 0 CHECK (pending >= 0),
	running INTEGER NOT NULL DEFAULT 0 CHECK (running >= 0)
) STRICT`

// Schema is the schema of the job state.
func Schema() store.Schema {
	return store.Schema{Owner: Owner, Migrations: []store.Migration{{Version: 1, SQL: stateTableSQL}}}
}

// DBStore keeps the records in the table jobs_state.
type DBStore struct{ DB *store.DB }

// micros stores a time as Unix microseconds, zero for the zero time.
func micros(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMicro()
}

func fromMicros(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.UnixMicro(v).UTC()
}

// Load returns every stored record.
func (s DBStore) Load(ctx context.Context) ([]Record, error) {
	var out []Record
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT name, last_run, last_end, last_error, pending, running FROM jobs_state ORDER BY name`)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var r Record
			var run, end int64
			if err := rows.Scan(&r.Name, &run, &end, &r.LastErr, &r.Pending, &r.Running); err != nil {
				return err
			}
			r.LastRun, r.LastEnd = fromMicros(run), fromMicros(end)
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("jobs: load state: %w", err)
	}
	return out, nil
}

// Save stores r.
func (s DBStore) Save(ctx context.Context, r Record) error {
	if r.Pending < 0 || r.Running < 0 {
		return errors.New("jobs: negative run count")
	}
	err := s.DB.Write(ctx, func(tx *store.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO jobs_state (name, last_run, last_end, last_error, pending, running)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT (name) DO UPDATE SET last_run = excluded.last_run, last_end = excluded.last_end,
				last_error = excluded.last_error, pending = excluded.pending, running = excluded.running`,
			r.Name, micros(r.LastRun), micros(r.LastEnd), r.LastErr, r.Pending, r.Running)
		return err
	})
	if err != nil {
		return fmt.Errorf("jobs: save state of %s: %w", r.Name, err)
	}
	return nil
}
