package accounts

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// Sessions ends the browser sessions of an account inside the caller's
// write transaction and announces their end after the commit (provided by
// internal/session). Without a session left it records an account-wide
// revocation, which ends the account's terminals and persistent tmux
// sessions in every process that follows the revocation journal.
type Sessions interface {
	RevokeAccountTx(ctx context.Context, tx *store.Tx, userID int64, reason principal.Reason) ([]principal.Revocation, error)
	Publish(revs []principal.Revocation)
}

// Warner is the warning level of the audit log (internal/audit). An
// Auditor without it writes administrator changes at the default level.
type Warner interface {
	SecurityWarning(event string, kv ...any)
}

// Actions of POST /admin/api/users/{user_id}/{action}.
const (
	ActionLock    = "lock"
	ActionUnlock  = "unlock"
	ActionPromote = "promote"
	ActionDemote  = "demote"
	ActionDelete  = "delete"
)

// Refusals of the account actions, with the Python wording.
var (
	ErrUnknownAction = fault.New(fault.InvalidValue, "Unknown action")
	ErrLockSelf      = fault.New(fault.InvalidValue, "You cannot lock your own account")
	ErrDeleteSelf    = fault.New(fault.InvalidValue, "You cannot delete your own account")
	ErrDeleteLast    = fault.New(fault.InvalidValue, "Cannot delete the last administrator")
)

func (s *Service) warn(event string, kv ...any) {
	if w, ok := s.Audit.(Warner); ok {
		w.SecurityWarning(event, kv...)
		return
	}
	if s.Audit != nil {
		s.Audit.Security(event, kv...)
	}
}

// getTx reads an account in the caller's transaction.
func getTx(ctx context.Context, tx *store.Tx, id int64) (Account, error) {
	a, err := scan(tx.QueryRowContext(ctx, `SELECT `+columns+` FROM accounts_users WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Account{}, errNotFound
	}
	return a, err
}

func adminCountTx(ctx context.Context, tx *store.Tx) (int, error) {
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM accounts_users WHERE is_admin = 1`).Scan(&n); err != nil {
		return 0, fmt.Errorf("accounts: count administrators: %w", err)
	}
	return n, nil
}

// InvalidateTx raises the account's auth_generation, which ends every
// credential issued before (sessions, pending sign-ins, step-up grants,
// known-device cookies), and ends its sessions and live resources for
// reason (invalidate_user_authentication and revoke_user_access). The
// caller publishes the revocations after the commit. Provider packages
// use it when a removed identity must not keep the access it gave (OIDC
// unlink).
func (s *Service) InvalidateTx(ctx context.Context, tx *store.Tx, id int64, reason principal.Reason) ([]principal.Revocation, error) {
	if _, err := s.RaiseGenerationTx(ctx, tx, id); err != nil {
		return nil, err
	}
	if s.Sessions == nil {
		return nil, nil
	}
	return s.Sessions.RevokeAccountTx(ctx, tx, id, reason)
}

// announce publishes committed revocations.
func (s *Service) announce(revs []principal.Revocation) {
	if s.Sessions != nil && len(revs) > 0 {
		s.Sessions.Publish(revs)
	}
}

func storage(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := fault.From(err); ok {
		return err
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return fault.Wrap(fault.StorageError, err, "")
}

// Manage applies lock, unlock, promote or demote to targetID for the
// administrator actor (admin_user_action). Every rule is checked inside
// the write transaction, so concurrent changes cannot demote the last
// administrator or promote a managed account. A lock ends every session
// and live resource of the account before Manage returns. Delete has its
// own method.
func (s *Service) Manage(ctx context.Context, actor principal.Principal, targetID int64, action string) (Account, error) {
	var acc Account
	var revs []principal.Revocation
	changed := false
	err := s.DB.Write(ctx, func(tx *store.Tx) error {
		var err error
		if acc, err = getTx(ctx, tx, targetID); err != nil {
			return err
		}
		self := acc.ID == actor.UserID
		switch action {
		case ActionLock:
			if self {
				return ErrLockSelf
			}
			if _, err := tx.ExecContext(ctx, `UPDATE accounts_users SET is_locked = 1 WHERE id = ?`, acc.ID); err != nil {
				return fmt.Errorf("accounts: lock: %w", err)
			}
			revs, err = s.InvalidateTx(ctx, tx, acc.ID, principal.ReasonAccountLocked)
			changed = true
		case ActionUnlock:
			_, err = tx.ExecContext(ctx, `UPDATE accounts_users SET is_locked = 0 WHERE id = ?`, acc.ID)
		case ActionPromote:
			if err := CheckPromote(acc); err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, `UPDATE accounts_users SET is_admin = 1 WHERE id = ?`, acc.ID)
		case ActionDemote:
			var n int
			if n, err = adminCountTx(ctx, tx); err != nil {
				return err
			}
			if err = s.CheckDemote(actor.UserID, acc, n); err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, `UPDATE accounts_users SET is_admin = 0 WHERE id = ?`, acc.ID)
		default:
			return ErrUnknownAction
		}
		if err != nil {
			return err
		}
		acc, err = getTx(ctx, tx, acc.ID)
		return err
	})
	if err != nil {
		return Account{}, storage(err)
	}
	if changed {
		s.announce(revs)
	}
	s.logger().Info("Admin user action", "admin", actor.Username, "user", acc.Username, "action", action)
	s.warn("ADMIN_USER_CHANGED", "admin", actor.Username, "user", acc.Username, "action", action)
	return acc, nil
}
