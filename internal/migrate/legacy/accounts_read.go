package legacy

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// AccountRow is one row of users with every column entity E01 takes over.
// Columns an older database lacks read with the values Python's
// ensure_user_columns gives existing rows.
type AccountRow struct {
	User
	LastLogin                 sql.NullString
	SettingsDefaultGeneration int64
	MFAFailedAttempts         int64
	MFALastFailedAt           sql.NullString
	StepUpFailedAttempts      int64
	StepUpLastFailedAt        sql.NullString
}

// AccountRows returns every account ordered by id.
func (s *Source) AccountRows(ctx context.Context) ([]AccountRow, error) {
	query := "SELECT " + s.schema.userSelect(s.restored != nil, "id", "username", "password_hash", "created_at", // #nosec G202 -- constant identifiers and literals
		"is_admin", "is_locked", "auth_generation", "mfa_enabled", "last_login", "settings_default_generation",
		"mfa_failed_attempts", "mfa_last_failed_at", "mfa_step_up_failed_attempts", "mfa_step_up_last_failed_at") +
		" FROM users ORDER BY id"
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("legacy: read users: %w", err)
	}
	defer rows.Close()
	var out []AccountRow
	for rows.Next() {
		var a AccountRow
		var lastLogin, mfaLast, stepLast any
		if err := rows.Scan(&a.ID, &a.Username, &a.PasswordHash, &a.CreatedAt, &a.IsAdmin, &a.IsLocked, &a.AuthGeneration,
			&a.MFAEnabled, &lastLogin, &a.SettingsDefaultGeneration, &a.MFAFailedAttempts, &mfaLast,
			&a.StepUpFailedAttempts, &stepLast); err != nil {
			return nil, fmt.Errorf("legacy: read users: %w", err)
		}
		a.LastLogin, a.MFALastFailedAt, a.StepUpLastFailedAt = dbText(lastLogin), dbText(mfaLast), dbText(stepLast)
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("legacy: read users: %w", err)
	}
	if !s.schema.HasColumn("users", "is_admin") && len(out) > 0 {
		out[0].IsAdmin = true
	}
	return out, nil
}

// dbText reads a DateTime column the way it is stored: SQLite returns
// text for SQLAlchemy's DateTime; a NULL stays invalid.
func dbText(v any) sql.NullString {
	switch v := v.(type) {
	case string:
		return sql.NullString{String: v, Valid: true}
	case []byte:
		return sql.NullString{String: string(v), Valid: true}
	case time.Time:
		return sql.NullString{String: v.UTC().Format("2006-01-02 15:04:05.000000"), Valid: true}
	}
	return sql.NullString{}
}

// dbTime converts a stored naive UTC timestamp to a time without loss of
// precision (migration specification, section 3: timestamps). A stored
// offset is applied. NULL is the zero time.
func dbTime(text sql.NullString) (time.Time, error) {
	if !text.Valid {
		return time.Time{}, nil
	}
	dt, err := pythonFromISOFormat(text.String)
	if err != nil {
		return time.Time{}, fmt.Errorf("legacy: unsupported timestamp %q", text.String)
	}
	t := dt.t
	if dt.hasOffset {
		t = t.Add(-dt.offset)
	}
	return t.UTC(), nil
}
