package automation

import (
	"context"
	"database/sql"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
)

// ScheduleSchemaVersion is the migration of the schedules table in the
// schema of owner "automation". The runbook part of the package adds its
// own tables to the same owner; the integration keeps one ordered list.
const ScheduleSchemaVersion = 1

// ScheduleSQL creates automation_schedules (entity E15). next_at and
// claimed_at are Unix seconds as the Python release stored them (REAL), so
// a migrated slot stays the same instant. approval is the frozen review
// with its bindings (scheduleApproval, JSON). There is no foreign key to
// the accounts: they belong to another owner.
const ScheduleSQL = `CREATE TABLE automation_schedules (
	id TEXT NOT NULL PRIMARY KEY,
	user_id INTEGER NOT NULL CHECK (user_id > 0),
	revision INTEGER NOT NULL CHECK (revision > 0),
	enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
	cron TEXT NOT NULL,
	timezone TEXT NOT NULL,
	next_at REAL NOT NULL,
	last_status TEXT NOT NULL,
	claim_id TEXT,
	claimed_at REAL,
	approval TEXT NOT NULL
) STRICT;
CREATE INDEX automation_schedules_user ON automation_schedules (user_id);
CREATE INDEX automation_schedules_due ON automation_schedules (enabled, next_at, id);`

// ScheduleSchema is the schema of the schedules.
func ScheduleSchema() store.Schema {
	return store.Schema{Owner: "automation", Migrations: []store.Migration{{Version: ScheduleSchemaVersion, SQL: ScheduleSQL}}}
}

// scheduleRow is one stored schedule.
type scheduleRow struct {
	ID         string
	UserID     int64
	Revision   int64
	Enabled    bool
	Cron       string
	Zone       string
	NextAt     float64
	LastStatus string
	ClaimID    sql.NullString
	ClaimedAt  sql.NullFloat64
	Approval   scheduleApproval
}

const scheduleColumns = `id, user_id, revision, enabled, cron, timezone, next_at, last_status, claim_id, claimed_at, approval`

type rowScanner interface{ Scan(dest ...any) error }

func scanSchedule(s rowScanner) (scheduleRow, error) {
	var r scheduleRow
	var approval string
	if err := s.Scan(&r.ID, &r.UserID, &r.Revision, &r.Enabled, &r.Cron, &r.Zone, &r.NextAt, &r.LastStatus,
		&r.ClaimID, &r.ClaimedAt, &approval); err != nil {
		return r, err
	}
	if err := json.Unmarshal([]byte(approval), &r.Approval); err != nil {
		return r, fmt.Errorf("automation: schedule %s: approval: %w", r.ID, err)
	}
	return r, nil
}

func querySchedules(ctx context.Context, tx *store.Tx, where string, args ...any) ([]scheduleRow, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+scheduleColumns+` FROM automation_schedules `+where, args...) // #nosec G202 -- constant clauses
	if err != nil {
		return nil, fmt.Errorf("automation: read schedules: %w", err)
	}
	defer rows.Close()
	var out []scheduleRow
	for rows.Next() {
		r, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// InsertScheduleTx stores a schedule row as it is (the migration of E15
// and new approvals).
func insertSchedule(ctx context.Context, tx *store.Tx, r scheduleRow) error {
	approval, err := json.Marshal(r.Approval)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO automation_schedules (`+scheduleColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.UserID, r.Revision, r.Enabled, r.Cron, r.Zone, r.NextAt, r.LastStatus, r.ClaimID, r.ClaimedAt, string(approval))
	if err != nil {
		return fmt.Errorf("automation: insert schedule: %w", err)
	}
	return nil
}

// exec runs a conditional update and reports whether it changed one row.
func execOne(ctx context.Context, tx *store.Tx, query string, args ...any) (bool, error) {
	res, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return false, fmt.Errorf("automation: update schedule: %w", err)
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// unixSeconds is a time as stored in next_at and claimed_at.
func unixSeconds(t time.Time) float64 {
	return float64(t.UnixMicro()) / 1e6
}

// fromUnixSeconds is the instant of a stored next_at, to the microsecond
// as Python's datetime.fromtimestamp.
func fromUnixSeconds(f float64) time.Time {
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(math.Round(frac*1e6))*1000).UTC()
}

// pythonISO is datetime.isoformat() of an aware UTC time.
func pythonISO(t time.Time) string {
	t = t.UTC()
	if t.Nanosecond()/1000 == 0 {
		return t.Format("2006-01-02T15:04:05") + "+00:00"
	}
	return t.Format("2006-01-02T15:04:05.000000") + "+00:00"
}

// storageFault keeps database failures out of answers.
func storageFault(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := errors.AsType[*fault.Error](err); ok {
		return err
	}
	return fault.Wrap(fault.StorageError, err, "")
}

// jsonOf marshals a value the package built itself.
func jsonOf(v any) jsontext.Value {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("automation: marshal %T: %v", v, err))
	}
	return b
}
