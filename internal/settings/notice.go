package settings

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
)

// NoticeUpgrade tells an account that the first-start migration took over
// from the 3.3 data that WebSSH 3.4 runs on a new server. The migration
// grants it to every account it takes over; accounts created later never
// get it.
const NoticeUpgrade = "upgrade-3.4"

// Notices are the one-time notices this release knows, in the order the
// pages show them.
var Notices = []string{NoticeUpgrade}

const (
	msgInvalidNotice  = "Invalid notice"
	msgNoticeNotSaved = "Could not save the notice"
)

// GrantNotice records notice as pending for an account in tx. A notice
// the account already has keeps its state, so granting never shows an
// acknowledged notice again.
func GrantNotice(ctx context.Context, tx *store.Tx, userID int64, notice string) error {
	if userID <= 0 || !in(Notices, notice) {
		return fmt.Errorf("settings: cannot grant notice %q to account %d", notice, userID)
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO settings_notices (user_id, notice) VALUES (?, ?)
ON CONFLICT (user_id, notice) DO NOTHING`, userID, notice)
	return err
}

// VerifyNotice checks that notice is recorded and still pending for an
// account; it is the verification of GrantNotice in the migration.
func VerifyNotice(ctx context.Context, tx *store.Tx, userID int64, notice string) error {
	var acknowledged sql.NullInt64
	err := tx.QueryRowContext(ctx, `SELECT acknowledged_us FROM settings_notices WHERE user_id = ? AND notice = ?`,
		userID, notice).Scan(&acknowledged)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("settings: account %d has no notice %q", userID, notice)
	case err != nil:
		return err
	case acknowledged.Valid:
		return fmt.Errorf("settings: notice %q of account %d is already acknowledged", notice, userID)
	}
	return nil
}

// Notices returns the notices the account has not acknowledged, in the
// order of Notices; an account without notices gets an empty list.
func (s *Service) Notices(ctx context.Context, userID int64) ([]string, error) {
	var out []string
	err := s.db.Read(ctx, func(tx *store.Tx) error {
		var err error
		out, err = pendingNotices(ctx, tx, userID)
		return err
	})
	if err != nil {
		return nil, storageFault(err)
	}
	return out, nil
}

// AcknowledgeNotice records that the account has read notice, so that no
// device shows it again. Acknowledging a notice the account does not have
// or has already acknowledged changes nothing. It returns the notices
// still pending.
func (s *Service) AcknowledgeNotice(ctx context.Context, userID int64, notice string) ([]string, error) {
	if userID <= 0 || !in(Notices, notice) {
		return nil, fault.New(fault.InvalidRequest, msgInvalidNotice)
	}
	at := max(s.now().UnixMicro(), 1)
	var out []string
	err := s.db.Write(ctx, func(tx *store.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE settings_notices SET acknowledged_us = ?
WHERE user_id = ? AND notice = ? AND acknowledged_us IS NULL`, at, userID, notice); err != nil {
			return err
		}
		var err error
		out, err = pendingNotices(ctx, tx, userID)
		return err
	})
	if err != nil {
		return nil, storageFault(err)
	}
	return out, nil
}

func pendingNotices(ctx context.Context, tx *store.Tx, userID int64) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT notice FROM settings_notices WHERE user_id = ? AND acknowledged_us IS NULL`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	found := map[string]bool{}
	for rows.Next() {
		var notice string
		if err := rows.Scan(&notice); err != nil {
			return nil, err
		}
		found[notice] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// A notice a later release granted is not shown by this one.
	out := []string{}
	for _, n := range Notices {
		if found[n] {
			out = append(out, n)
		}
	}
	return out, nil
}
