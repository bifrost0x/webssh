package settings

import (
	"context"
	"database/sql"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"time"

	"github.com/bifrost0x/webssh/internal/store"
)

// keyRecoveryCheck is the application setting of the notice after a
// portable restore (recovery-check.json of the Python release, A07).
const keyRecoveryCheck = "recovery_check"

// MarkRestoredTx sets the notice of a portable restore: every account is
// asked once to review its hosts and credentials (mark_restore_recovery).
// The restore calls it on the restored database.
func MarkRestoredTx(ctx context.Context, tx *store.Tx, at time.Time) error {
	v, err := json.Marshal(map[string]any{"restored_at": PythonISOTime(at), "remote_credentials_excluded": true},
		json.Deterministic(true))
	if err != nil {
		return err
	}
	return putApp(ctx, tx, keyRecoveryCheck, v, SourceAdmin, "", at.UnixMicro())
}

// PythonISOTime is datetime.isoformat() of an aware UTC time: microseconds
// only when they are not zero, and the offset +00:00.
func PythonISOTime(t time.Time) string {
	t = t.UTC()
	out := t.Format("2006-01-02T15:04:05")
	if us := t.Nanosecond() / 1000; us != 0 {
		out += fmt.Sprintf(".%06d", us)
	}
	return out + "+00:00"
}

// ValidRecoveryTime is valid_recovery_timestamp: a string of 1 to 64
// characters that is an ISO 8601 time with a UTC offset.
func ValidRecoveryTime(s string) bool {
	if n := len([]rune(s)); n < 1 || n > 64 {
		return false
	}
	for _, layout := range []string{"2006-01-02T15:04:05.999999999Z07:00", "2006-01-02 15:04:05.999999999Z07:00",
		"2006-01-02T15:04Z07:00", "2006-01-02T15Z07:00"} {
		if _, err := time.Parse(layout, s); err == nil {
			return true
		}
	}
	return false
}

// restoreMarker is _restore_marker: the time of the last portable
// restore, or "" when there is none or the stored notice is malformed
// (never proof of restored credentials).
func restoreMarker(ctx context.Context, tx *store.Tx) (string, error) {
	var raw string
	err := tx.QueryRowContext(ctx, `SELECT value FROM settings_app WHERE key = ?`, keyRecoveryCheck).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if len(raw) > 512 {
		return "", nil
	}
	var doc map[string]jsontext.Value
	if json.Unmarshal([]byte(raw), &doc) != nil {
		return "", nil
	}
	var at string
	if v, ok := doc["restored_at"]; !ok || v.Kind() != '"' || json.Unmarshal(v, &at) != nil || !ValidRecoveryTime(at) {
		return "", nil
	}
	return at, nil
}

// RecoveryCheck returns the time of the last portable restore ("" when
// there is none) and whether the account has not reviewed it yet.
func (s *Service) RecoveryCheck(ctx context.Context, userID int64) (restoredAt string, needsReview bool, err error) {
	err = s.db.Read(ctx, func(tx *store.Tx) error {
		if restoredAt, err = restoreMarker(ctx, tx); err != nil || restoredAt == "" {
			return err
		}
		stored, err := storedUser(ctx, tx, userID)
		if err != nil {
			return err
		}
		var reviewed string
		if v, ok := stored[keyRecoveryReviewedAt]; ok {
			_ = json.Unmarshal(v, &reviewed)
		}
		needsReview = reviewed != restoredAt
		return nil
	})
	return restoredAt, needsReview, storageFault(err)
}

// ReviewRecovery records that the account reviewed the restore of
// restoredAt. It reports false, changing nothing, when that is not the
// current restore (a newer restore must be reviewed afresh).
func (s *Service) ReviewRecovery(ctx context.Context, userID int64, restoredAt string) (bool, error) {
	ok := false
	err := s.db.Write(ctx, func(tx *store.Tx) error {
		current, err := restoreMarker(ctx, tx)
		if err != nil || current == "" || current != restoredAt {
			return err
		}
		ok = true
		return putUser(ctx, tx, userID, keyRecoveryReviewedAt, marshalValue(current))
	})
	return ok, storageFault(err)
}
