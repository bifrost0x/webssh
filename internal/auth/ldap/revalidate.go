package ldap

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

var _ auth.Revalidator = (*Service)(nil)

var (
	errSignedOut  = fault.New(fault.AuthenticationNeeded, "")
	errInProgress = func() error {
		e := fault.New(fault.LDAPValidationInProgress, "Directory session validation is in progress")
		e.RetryAfter = time.Second
		return e
	}()
	errIneligible = fmt.Errorf("%w: LDAP account is not eligible", ErrRejected)
	errMismatch   = fmt.Errorf("%w: stable LDAP identity no longer matches", ErrRejected)
)

// standing is what the checks read of an LDAP-managed account.
type standing struct {
	identity Identity
	account  Account
	required bool
	checked  time.Time
}

// standingOf reads the identity, account and revalidation state; found
// is false for an account without LDAP identity.
func (s *Service) standingOf(ctx context.Context, userID int64) (standing, bool, error) {
	var st standing
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		if st.identity, err = identityOfTx(ctx, tx, userID); err != nil {
			return err
		}
		if st.account, err = s.Accounts.GetTx(ctx, tx, userID); err != nil {
			return err
		}
		st.required, st.checked, err = RevalidationTx(ctx, tx, userID)
		return err
	})
	switch {
	case errors.Is(err, errNoIdentity):
		return standing{}, false, nil
	case fault.Is(err, fault.NotFound):
		return standing{}, false, nil
	case err != nil:
		return standing{}, false, fault.Wrap(fault.StorageError, err, "")
	}
	return st, true, nil
}

// Gate runs before every request of a signed-in account (the before-
// request checks of the Python release). An account without LDAP identity
// passes. An LDAP-managed account is signed out when LDAP is off or a
// directory check is required, and is checked again when its last check
// is older than LDAP_SESSION_REVALIDATION_SECONDS. While another request
// checks the account, the request is refused with
// ldap_validation_in_progress and may be retried.
func (s *Service) Gate(ctx context.Context, p principal.Principal) error {
	st, found, err := s.standingOf(ctx, p.UserID)
	if err != nil || !found {
		return err
	}
	switch {
	case !s.Enabled || s.Directory == nil:
		return s.refuse(ctx, p.UserID, "disabled")
	case st.required:
		return s.refuse(ctx, p.UserID, "pending_invalidation")
	case s.now().Sub(st.checked) < s.Revalidation:
		return nil
	}
	if !s.claim(p.UserID) {
		return errInProgress
	}
	defer s.release(p.UserID)
	if err := s.check(ctx, p.UserID); err != nil {
		s.logger().WarnContext(ctx, "LDAP session revalidation rejected", "user", p.Username, "error", err)
		return s.refuse(ctx, p.UserID, "revalidation")
	}
	return nil
}

// refuse invalidates the account's credentials and answers the request as
// signed out.
func (s *Service) refuse(ctx context.Context, userID int64, reason string) error {
	if err := s.invalidate(ctx, userID); err != nil {
		s.logger().ErrorContext(ctx, "LDAP access invalidation failed", "user_id", userID, "reason", reason, "error", err)
		return fault.Wrap(fault.Unavailable, err, "")
	}
	return errSignedOut
}

// Revalidate checks an account against the directory and ends its access
// when the check fails; an unreachable directory counts as failed (fail
// closed). It implements auth.Revalidator.
func (s *Service) Revalidate(ctx context.Context, userID int64) error {
	if err := s.check(ctx, userID); err != nil {
		if ierr := s.invalidate(ctx, userID); ierr != nil {
			return errors.Join(err, ierr)
		}
		return err
	}
	return nil
}

// check looks the stored directory name up again and compares the
// binding (revalidate_user). The account must be active, not an
// administrator and still linked.
func (s *Service) check(ctx context.Context, userID int64) error {
	if !s.Enabled || s.Directory == nil {
		return fmt.Errorf("%w: LDAP is disabled", ErrUnavailable)
	}
	st, found, err := s.standingOf(ctx, userID)
	if err != nil {
		return err
	}
	if !found || st.account.IsLocked || st.account.IsAdmin {
		return errIneligible
	}
	entry, err := s.Directory.Lookup(ctx, st.identity.DirectoryUsername)
	if err != nil {
		return err
	}
	if st.identity.Provider != s.Provider || entry.Subject != st.identity.Subject {
		return errMismatch
	}
	err = s.DB.Write(ctx, func(tx *store.Tx) error {
		// Record the check only for the identity that was checked; a
		// relink or unlink meanwhile starts over.
		cur, err := identityOfTx(ctx, tx, userID)
		if err != nil {
			return err
		}
		if cur.ID != st.identity.ID || cur.Subject != st.identity.Subject {
			return errMismatch
		}
		if required, _, err := RevalidationTx(ctx, tx, userID); err != nil || required {
			return errors.Join(err, errIneligible)
		}
		return checkedTx(ctx, tx, userID, s.now())
	})
	if errors.Is(err, errNoIdentity) {
		return errIneligible
	}
	return err
}

// invalidate ends every credential of the account: the auth generation is
// raised and every session ends with the reason directory_refused, which
// closes its terminals as a lock does
// (persist_ldap_authentication_invalidation).
func (s *Service) invalidate(ctx context.Context, userID int64) error {
	err := s.DB.Write(ctx, func(tx *store.Tx) error { return s.Accounts.RaiseGenerationTx(ctx, tx, userID) })
	if err != nil && !fault.Is(err, fault.NotFound) {
		return err
	}
	_, rerr := s.Sessions.RevokeUser(ctx, userID, principal.ReasonDirectoryRefused, "")
	return rerr
}

func (s *Service) claim(userID int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.checking[userID] {
		return false
	}
	if s.checking == nil {
		s.checking = map[int64]bool{}
	}
	s.checking[userID] = true
	return true
}

func (s *Service) release(userID int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.checking, userID)
}

// Sweep checks every linked account once (revalidate_all_linked_users),
// the periodic job of LDAP_SESSION_REVALIDATION_SECONDS. An account
// checked after the sweep started is skipped; an account that must pass a
// check loses its sessions until it signs in again. It returns the number
// of accounts whose access ended.
func (s *Service) Sweep(ctx context.Context) (int, error) {
	started := s.now()
	var ids []Identity
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		ids, err = IdentitiesTx(ctx, tx)
		return err
	})
	if err != nil {
		return 0, fault.Wrap(fault.StorageError, err, "")
	}
	ended := 0
	for _, id := range ids {
		if ctx.Err() != nil {
			return ended, ctx.Err()
		}
		st, found, err := s.standingOf(ctx, id.UserID)
		if err != nil {
			return ended, err
		}
		switch {
		case !found:
			continue
		case st.required:
			if _, err := s.Sessions.RevokeUser(ctx, id.UserID, principal.ReasonDirectoryRefused, ""); err != nil {
				s.audit("LDAP_BACKGROUND_AUTHENTICATION_INVALIDATION_FAILED", "user", st.account.Username, "error", "storage")
			}
			continue
		case !st.checked.Before(started):
			continue
		}
		if !s.claim(id.UserID) {
			continue
		}
		err = s.check(ctx, id.UserID)
		s.release(id.UserID)
		if err == nil {
			continue
		}
		s.audit("LDAP_BACKGROUND_REVALIDATION_REJECTED", "user", st.account.Username, "error", errorKind(err))
		if ierr := s.invalidate(ctx, id.UserID); ierr != nil {
			s.audit("LDAP_BACKGROUND_AUTHENTICATION_INVALIDATION_FAILED", "user", st.account.Username, "error", "storage")
			continue
		}
		ended++
	}
	return ended, nil
}

// errorKind names a failure for the audit log without directory text, as
// the Python release logged the exception class.
func errorKind(err error) string {
	if errors.Is(err, ErrRejected) {
		return "LDAPLookupRejected"
	}
	return "LDAPUnavailable"
}
