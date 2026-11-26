package accounts

import (
	"context"
	"fmt"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
)

// CreateRequest describes a new local account (register_user).
type CreateRequest struct {
	Username string
	Password string
	// FirstOnly closes the browser bootstrap: the account is created only
	// if no account exists yet, atomically with the check.
	FirstOnly bool
	// ByAdmin allows a name reserved by ADMIN_USERS; the first account may
	// take one as well, because it becomes administrator regardless.
	ByAdmin bool
	// Admin grants administrator rights; the first account always gets
	// them.
	Admin bool
}

var (
	errRegistrationClosed = fault.New(fault.Forbidden, "Registration is currently disabled.")
	errNameTaken          = fault.New(fault.InvalidValue, "Username already exists")
)

func invalid(msg string) error { return fault.New(fault.InvalidValue, msg) }

// Create validates and stores a new local account with its password. The
// name and first-account checks run again inside the write transaction,
// so concurrent registrations cannot both become the first account or
// take the same name. The password is hashed before the transaction.
func (s *Service) Create(ctx context.Context, req CreateRequest) (Account, error) {
	if err := s.precheck(ctx, req); err != nil {
		return Account{}, err
	}
	hash, err := s.Credentials.Hash(ctx, req.Password)
	if err != nil {
		return Account{}, err
	}
	var acc Account
	var first bool
	err = s.DB.Write(ctx, func(tx *store.Tx) error {
		var err error
		acc, first, err = s.createTx(ctx, tx, req, hash)
		return err
	})
	if err != nil {
		if _, ok := fault.From(err); ok {
			return Account{}, err
		}
		return Account{}, fault.Wrap(fault.StorageError, err, "")
	}
	if first && s.Audit != nil {
		s.Audit.Security("INITIAL_ADMIN_REGISTERED", "user", acc.Username)
	}
	return acc, nil
}

// precheck gives the Python messages in the Python order before the
// password is hashed.
func (s *Service) precheck(ctx context.Context, req CreateRequest) error {
	var count int
	var names []string
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		count, names, err = existing(ctx, tx)
		return err
	})
	if err != nil {
		return fault.Wrap(fault.StorageError, err, "")
	}
	return s.validate(req, count == 0, names)
}

func (s *Service) validate(req CreateRequest, first bool, names []string) error {
	if req.FirstOnly && !first {
		return errRegistrationClosed
	}
	if msg := validateNewName(req.Username); msg != "" {
		return invalid(msg)
	}
	folded := foldName(req.Username)
	for _, n := range names {
		if foldName(n) == folded {
			return errNameTaken
		}
	}
	if !req.ByAdmin && !first && s.Admins.Reserves(req.Username) {
		s.logger().Info("Account name refused: reserved by ADMIN_USERS", "user", req.Username, "source", "registration")
		return errNameTaken
	}
	if msg := s.Credentials.ValidateNew(req.Password); msg != "" {
		return invalid(msg)
	}
	return nil
}

func existing(ctx context.Context, tx *store.Tx) (int, []string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT username FROM accounts_users`)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return 0, nil, err
		}
		names = append(names, n)
	}
	return len(names), names, rows.Err()
}

func (s *Service) createTx(ctx context.Context, tx *store.Tx, req CreateRequest, hash string) (Account, bool, error) {
	count, names, err := existing(ctx, tx)
	if err != nil {
		return Account{}, false, err
	}
	first := count == 0
	if err := s.validate(req, first, names); err != nil {
		return Account{}, false, err
	}
	var id int64
	if err := tx.QueryRowContext(ctx, `SELECT max((SELECT coalesce(max(id), 0) FROM accounts_users),
		(SELECT value FROM accounts_id_floor WHERE singleton = 1)) + 1`).Scan(&id); err != nil {
		return Account{}, false, fmt.Errorf("accounts: next id: %w", err)
	}
	now := s.now()
	inc := pyISO(now)
	acc := Account{ID: id, Username: req.Username, Incarnation: inc, HistoryGeneration: inc, CreatedAt: now.Truncate(time.Microsecond), IsAdmin: first || req.Admin}
	if _, err := tx.ExecContext(ctx, `INSERT INTO accounts_users (id, username, incarnation, history_generation, created_us, is_admin)
		VALUES (?, ?, ?, ?, ?, ?)`, id, acc.Username, inc, inc, now.UnixMicro(), acc.IsAdmin); err != nil {
		return Account{}, false, fmt.Errorf("accounts: insert: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE accounts_id_floor SET value = ? WHERE singleton = 1`, id); err != nil {
		return Account{}, false, fmt.Errorf("accounts: raise id floor: %w", err)
	}
	if err := s.Credentials.StoreTx(ctx, tx, id, hash); err != nil {
		return Account{}, false, err
	}
	return acc, first, nil
}

// HasAccounts reports whether any account exists; the browser bootstrap
// is available only while it is false (is_bootstrap_registration_available).
func (s *Service) HasAccounts(ctx context.Context) (bool, error) {
	var n int
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM (SELECT 1 FROM accounts_users LIMIT 1)`).Scan(&n)
	})
	if err != nil {
		return false, fault.Wrap(fault.StorageError, err, "")
	}
	return n > 0, nil
}
