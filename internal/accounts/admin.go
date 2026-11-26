package accounts

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
)

// Normalize applies the start-up rules of the Python release, in its
// order: ensure_initial_admin (the oldest local account becomes
// administrator when no local administrator exists), then
// sync_admin_users (listed accounts that are not locked and not managed
// by a directory or GitHub are promoted; nobody is demoted). The
// composition root runs it before serving.
func (s *Service) Normalize(ctx context.Context) error {
	if err := s.ensureInitialAdmin(ctx); err != nil {
		return err
	}
	return s.syncAdminUsers(ctx)
}

func (s *Service) ensureInitialAdmin(ctx context.Context) error {
	var repaired string
	err := s.DB.Write(ctx, func(tx *store.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM accounts_users WHERE is_admin = 1 AND managed_by = ''`).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return nil
		}
		err := tx.QueryRowContext(ctx, `UPDATE accounts_users SET is_admin = 1
			WHERE id = (SELECT min(id) FROM accounts_users WHERE managed_by = '') RETURNING username`).Scan(&repaired)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	})
	if err != nil {
		return fmt.Errorf("accounts: ensure initial admin: %w", err)
	}
	if repaired != "" && s.Audit != nil {
		s.Audit.Security("INITIAL_ADMIN_REPAIRED", "user", repaired)
	}
	return nil
}

func (s *Service) syncAdminUsers(ctx context.Context) error {
	for _, name := range s.Admins {
		var promoted bool
		var exists bool
		err := s.DB.Write(ctx, func(tx *store.Tx) error {
			a, err := scan(tx.QueryRowContext(ctx, `SELECT `+columns+` FROM accounts_users WHERE username = ?`, name))
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			if err != nil {
				return err
			}
			exists = true
			if a.IsAdmin || a.IsLocked || a.Managed != ManagedLocal {
				return nil
			}
			promoted = true
			_, err = tx.ExecContext(ctx, `UPDATE accounts_users SET is_admin = 1 WHERE id = ?`, a.ID)
			return err
		})
		if err != nil {
			return fmt.Errorf("accounts: sync ADMIN_USERS: %w", err)
		}
		switch {
		case !exists:
			// Whoever registers this name later would become admin on the
			// next start; registration therefore refuses the name.
			s.logger().Warn("ADMIN_USERS lists an account that does not exist; remove it or create the account", "user", name)
		case promoted:
			s.logger().Info("Admin granted via ADMIN_USERS", "user", name)
		}
	}
	return nil
}

// Refusals of the administrator rules, with the Python wording.
var (
	ErrDemoteSelf    = fault.New(fault.InvalidValue, "You cannot remove your own admin rights")
	ErrDemoteLast    = fault.New(fault.InvalidValue, "Cannot demote the last administrator")
	ErrDemoteManaged = fault.New(fault.Conflict, "This account is an administrator through the ADMIN_USERS setting; remove it from ADMIN_USERS and restart before demoting it")
	ErrConversion    = fault.New(fault.Conflict, "This account is listed in ADMIN_USERS. Remove it from ADMIN_USERS before converting it to a local account.")
	ErrPromoteLDAP   = fault.New(fault.InvalidValue, "LDAP accounts cannot be administrators; keep a local break-glass administrator")
	ErrPromoteGitHub = fault.New(fault.InvalidValue, "GitHub-managed accounts cannot be administrators; keep a local break-glass administrator")
)

// CheckDemote applies the demote rules of the admin panel. admins is the
// number of administrators. M1 answers the demote route with 501; the
// rule is built here so B2 only wires it.
func (s *Service) CheckDemote(actorID int64, target Account, admins int) error {
	switch {
	case target.ID == actorID:
		return ErrDemoteSelf
	case target.IsAdmin && admins <= 1:
		return ErrDemoteLast
	case s.Admins.Manages(target):
		return ErrDemoteManaged
	}
	return nil
}

// CheckPromote refuses administrator rights for directory- and
// GitHub-managed accounts.
func CheckPromote(target Account) error {
	switch target.Managed {
	case ManagedLDAP:
		return ErrPromoteLDAP
	case ManagedGitHub:
		return ErrPromoteGitHub
	}
	return nil
}

// CheckLocalConversion refuses to turn a listed LDAP or GitHub account
// into a local one: the start-up rule would promote it on the next start.
func (s *Service) CheckLocalConversion(target Account) error {
	if target.Managed != ManagedLocal && s.Admins.Reserves(target.Username) {
		return ErrConversion
	}
	return nil
}
