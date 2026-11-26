package settings

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
)

// errCorrupt marks a stored value that no longer passes its check.
var errCorrupt = errors.New("settings: stored value is invalid")

// Service reads and writes the account and application settings. It is
// safe for concurrent use; writes are serialized by the store.
type Service struct {
	db  *store.DB
	env Environment
	now func() time.Time
}

// New returns the service on db, which must have Schema applied; env is
// what application settings fall back to.
func New(db *store.DB, env Environment) *Service {
	return &Service{db: db, env: env, now: time.Now}
}

// User returns the effective settings of an account. An account without
// stored values gets the defaults.
func (s *Service) User(ctx context.Context, userID int64) (User, error) {
	var u User
	err := s.db.Read(ctx, func(tx *store.Tx) error {
		var err error
		u, err = readUser(ctx, tx, userID)
		return err
	})
	if err != nil {
		return User{}, storageFault(err)
	}
	return u, nil
}

// Update applies changes in one transaction and returns the settings as
// stored afterwards, so that callers answer with the stored value and not
// with the requested one.
func (s *Service) Update(ctx context.Context, userID int64, c Changes) (User, error) {
	if userID <= 0 {
		return User{}, fault.New(fault.InvalidRequest, "")
	}
	rows, err := c.rows()
	if err != nil {
		return User{}, err
	}
	var u User
	err = s.db.Write(ctx, func(tx *store.Tx) error {
		for key, v := range rows {
			if err := putUser(ctx, tx, userID, key, v); err != nil {
				return err
			}
		}
		u, err = readUser(ctx, tx, userID)
		return err
	})
	if err != nil {
		return User{}, storageFault(err)
	}
	return u, nil
}

// SetOnboarding records the state of the introduction tour directly; the
// end-to-end seed uses it to start accounts with the tour seen.
func (s *Service) SetOnboarding(ctx context.Context, userID int64, tour string, v3Acknowledged bool) error {
	if !in(TourStates, tour) || userID <= 0 {
		return invalid(msgInvalidTourState)
	}
	return storageFault(s.db.Write(ctx, func(tx *store.Tx) error {
		if err := putUser(ctx, tx, userID, keyIntroTour, marshalValue(tour)); err != nil {
			return err
		}
		return putUser(ctx, tx, userID, keyIntroTourV3Ack, marshalValue(v3Acknowledged))
	}))
}

// DeleteUser removes the settings of an account; the account lifecycle
// calls it in the transaction that removes the account.
func DeleteUser(ctx context.Context, tx *store.Tx, userID int64) error {
	_, err := tx.ExecContext(ctx, `DELETE FROM settings_user WHERE user_id = ?`, userID)
	return err
}

func readUser(ctx context.Context, tx *store.Tx, userID int64) (User, error) {
	stored, err := storedUser(ctx, tx, userID)
	if err != nil {
		return User{}, err
	}
	u, ok := buildUser(stored)
	if !ok {
		return User{}, fmt.Errorf("%w: account %d", errCorrupt, userID)
	}
	return u, nil
}

func storedUser(ctx context.Context, tx *store.Tx, userID int64) (map[string]jsontext.Value, error) {
	rows, err := tx.QueryContext(ctx, `SELECT key, value FROM settings_user WHERE user_id = ?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	stored := map[string]jsontext.Value{}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		v := jsontext.Value(value)
		if !v.IsValid() {
			return nil, fmt.Errorf("%w: %s", errCorrupt, key)
		}
		stored[key] = v
	}
	return stored, rows.Err()
}

func putUser(ctx context.Context, tx *store.Tx, userID int64, key string, v jsontext.Value) error {
	if !validStored(key, v) {
		return fmt.Errorf("%w: %s", errCorrupt, key)
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO settings_user (user_id, key, value) VALUES (?, ?, ?)
ON CONFLICT (user_id, key) DO UPDATE SET value = excluded.value`, userID, key, string(v))
	return err
}

// storageFault classifies an error of the store; fault errors pass.
func storageFault(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := fault.From(err); ok {
		return err
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fault.Wrap(fault.Unavailable, err, "")
	}
	return fault.Wrap(fault.StorageError, err, "")
}
