package accounts

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// RetainedPath is the location of a retained copy relative to DATA_DIR,
// as the audit log names it.
func RetainedPath(name string) string { return "go/deleted_users/" + name }

// LegacyUserDir reports the data directory of the Python release that
// belonged to a user id ("users/user_<id>" relative to DATA_DIR) when it
// exists. The directory is never changed (invariant I-01); a deletion only
// records it in the quarantine index so that no Go path ever maps it to
// another account. Nil means there is no legacy data directory.
type LegacyUserDir func(userID int64) (relPath string, exists bool)

var errDeleteFailed = errors.New("accounts: deletion failed")

// msgDeleteFailed is the Python answer when the deletion fails after the
// account was locked.
const msgDeleteFailed = "User deletion failed; the account remains locked"

// Delete removes the account targetID for the administrator actor
// (admin_user_action "delete", user_lifecycle.delete_user_account).
//
// It runs in two steps like the Python release. The first locks the
// account, raises its auth_generation and ends every session and live
// resource (terminals including tmux) before anything is removed. The
// second writes and verifies a copy of every row the account owns
// (Retainer), then removes, in the same transaction, exactly those rows
// from every store (passkeys, second factors, recovery codes, keys, hosts,
// settings, notes, step-up state, persistent sessions; UserData), records the
// legacy data directory of the id in the quarantine index, and deletes
// the account. If the second step fails, nothing of it is applied and the
// account stays locked. The id is never handed out again (id floor).
func (s *Service) Delete(ctx context.Context, actor principal.Principal, targetID int64) error {
	var acc Account
	var revs []principal.Revocation
	err := s.DB.Write(ctx, func(tx *store.Tx) error {
		var err error
		if acc, err = getTx(ctx, tx, targetID); err != nil {
			return err
		}
		if acc.ID == actor.UserID {
			return ErrDeleteSelf
		}
		if acc.IsAdmin {
			n, err := adminCountTx(ctx, tx)
			if err != nil {
				return err
			}
			if n <= 1 {
				return ErrDeleteLast
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE accounts_users SET is_locked = 1 WHERE id = ?`, acc.ID); err != nil {
			return fmt.Errorf("accounts: lock before deletion: %w", err)
		}
		revs, err = s.InvalidateTx(ctx, tx, acc.ID, principal.ReasonAccountLocked)
		return err
	})
	if err != nil {
		return storage(err)
	}
	s.announce(revs)

	var removed map[string]int64
	var kept Retained
	err = s.DB.Write(ctx, func(tx *store.Tx) error {
		current, err := getTx(ctx, tx, acc.ID)
		if err != nil {
			return err
		}
		if s.Data == nil || s.Retain == nil {
			return errors.Join(errDeleteFailed, errors.New("no account data owner or retained copy is wired"))
		}
		tables, err := s.Data.TablesTx(ctx, tx)
		if err != nil {
			return err
		}
		// The copy is written and verified before anything is removed; a
		// failed copy leaves the account in place (locked).
		if kept, err = s.Retain.RetainTx(ctx, tx, current, tables); err != nil {
			return err
		}
		if removed, err = s.Data.DeleteUserTx(ctx, tx, acc.ID); err != nil {
			return err
		}
		for _, table := range tables {
			if removed[table] != kept.Rows[table] {
				return fmt.Errorf("accounts: %s: removed %d rows, the retained copy holds %d", table, removed[table], kept.Rows[table])
			}
		}
		if s.LegacyDir != nil {
			if rel, ok := s.LegacyDir(acc.ID); ok {
				if _, err := tx.ExecContext(ctx, `INSERT INTO accounts_quarantine (path, former_user_id, found_us) VALUES (?, ?, ?)
					ON CONFLICT (path) DO UPDATE SET former_user_id = excluded.former_user_id, found_us = excluded.found_us`,
					rel, acc.ID, s.now().UnixMicro()); err != nil {
					return fmt.Errorf("accounts: record legacy directory: %w", err)
				}
			}
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM accounts_users WHERE id = ?`, acc.ID)
		if err != nil {
			return fmt.Errorf("accounts: delete: %w", err)
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return errors.Join(errDeleteFailed, err)
		}
		return nil
	})
	if err != nil {
		if kept.Discard != nil {
			if derr := kept.Discard(); derr != nil {
				s.logger().Error("Retained copy of an account that was not deleted could not be removed", "user", acc.Username,
					"copy", kept.Name, "error", derr)
			}
		}
		if fault.Is(err, fault.NotFound) {
			return err
		}
		s.logger().Error("Admin user deletion failed", "admin", actor.Username, "user", acc.Username, "error", err)
		return fault.Wrap(fault.Internal, err, msgDeleteFailed)
	}
	kv := []any{"admin", actor.Username, "user", acc.Username}
	for _, table := range sortedKeys(removed) {
		kv = append(kv, "rows_"+table, strconv.FormatInt(removed[table], 10))
	}
	s.logger().Warn("Admin deleted user", kv...)
	s.warn("ADMIN_USER_DELETED", "admin", actor.Username, "user", acc.Username, "retained", RetainedPath(kept.Name))
	return nil
}
