package ldap

import (
	"context"
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// maxProvisionedNameRunes bounds the name of an auto-provisioned account
// (_MAX_AUTO_PROVISIONED_USERNAME_LENGTH).
const maxProvisionedNameRunes = 80

// Authenticate is the LDAP sign-in of POST /login/ldap (ldap_login): the
// service account looks the name up, the identity must be linked to an
// active non-admin account (or LDAP_AUTO_PROVISION creates one after the
// password is verified), and the user's own bind proves the password.
// Every refusal is fault.AuthFailed; a directory without a verdict is
// fault.Unavailable, which the flow does not count as a failed attempt.
//
// The name is the submitted form value; it is stripped as in Python.
func (s *Service) Authenticate(ctx context.Context, presented, password string) (int64, error) {
	if !s.active(ctx) {
		return 0, errUnavailable
	}
	username := pyStrip(presented)
	entry, err := s.Directory.Lookup(ctx, username)
	if err != nil {
		return 0, classify(err, errUnavailable)
	}
	linked, found, err := s.linkedIdentity(ctx, entry)
	if err != nil {
		return 0, err
	}
	if !found && !s.AutoProvision {
		return 0, errAuthFailed
	}
	ok, err := s.Directory.VerifyPassword(ctx, entry.DN, password)
	if err != nil {
		return 0, classify(err, errUnavailable)
	}
	if !ok {
		return 0, errAuthFailed
	}
	if !found {
		if linked, err = s.provision(ctx, username, presented, entry); err != nil {
			return 0, err
		}
	}
	if err := s.signedIn(ctx, linked.UserID, username, entry); err != nil {
		return 0, err
	}
	return linked.UserID, nil
}

// linkedIdentity returns the identity of entry. An identity of a locked
// or admin account is a refusal, as in the Python release.
func (s *Service) linkedIdentity(ctx context.Context, entry Entry) (Identity, bool, error) {
	var id Identity
	var acc Account
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		id, err = identityBySubjectTx(ctx, tx, s.Provider, entry.Subject)
		if errors.Is(err, errNoIdentity) && entry.LegacySubject != "" {
			if id, err = identityBySubjectTx(ctx, tx, s.Provider, entry.LegacySubject); err == nil && !entry.matches(id) {
				return errAmbiguousSubject
			}
		}
		if err != nil {
			return err
		}
		acc, err = s.Accounts.GetTx(ctx, tx, id.UserID)
		return err
	})
	switch {
	case errors.Is(err, errNoIdentity):
		return Identity{}, false, nil
	case errors.Is(err, errAmbiguousSubject):
		// The binding was stored under a subject that other entries share
		// and was recorded for another entry: an administrator relinks it.
		s.audit("LDAP_LOGIN_REJECTED", "dn", entry.DN, "reason", "ambiguous_subject", "user_id", id.UserID)
		return Identity{}, false, errAuthFailed
	case fault.Is(err, fault.NotFound):
		return Identity{}, false, errAuthFailed
	case err != nil:
		return Identity{}, false, fault.Wrap(fault.StorageError, err, "")
	case acc.IsLocked || acc.IsAdmin:
		return Identity{}, false, errAuthFailed
	}
	return id, true, nil
}

// signedIn records the successful sign-in: the directory name and DN of
// the entry, the verification time and the passed directory check. An
// account that still had to pass a check (E37, a refused revalidation)
// loses its earlier sessions first; the new session is the first after
// the check.
//
// A binding stored under the ambiguous Python subject of the entry moves
// to the entry's own subject, so no other entry can match it afterwards.
func (s *Service) signedIn(ctx context.Context, userID int64, username string, entry Entry) error {
	now := s.now()
	var required bool
	var revs []principal.Revocation
	err := s.DB.Write(ctx, func(tx *store.Tx) error {
		var err error
		if required, _, err = RevalidationTx(ctx, tx, userID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE authldap_identities SET directory_username = ?, distinguished_name = ?,
			subject = CASE WHEN subject = ? THEN ? ELSE subject END, last_verified_us = ? WHERE user_id = ?`,
			username, entry.DN, entry.LegacySubject, entry.Subject, now.UnixMicro(), userID); err != nil {
			return fmt.Errorf("ldap: record sign-in: %w", err)
		}
		if required {
			if err := s.Accounts.RaiseGenerationTx(ctx, tx, userID); err != nil {
				return err
			}
			if revs, err = s.Sessions.RevokeAccountTx(ctx, tx, userID, principal.ReasonDirectoryRefused); err != nil {
				return err
			}
		}
		return checkedTx(ctx, tx, userID, now)
	})
	if err != nil {
		return fault.Wrap(fault.StorageError, err, "")
	}
	s.Sessions.Publish(revs)
	return nil
}

// provision creates the account of a verified directory identity
// (_auto_provision_ldap_identity): a name of at most 80 characters without
// control or unassigned characters, a local break-glass administrator,
// and no account whose name equals it after case folding. A concurrent
// sign-in that provisioned the same identity first wins; its account is
// used.
func (s *Service) provision(ctx context.Context, username, presented string, entry Entry) (Identity, error) {
	if username == "" || utf8.RuneCountInString(username) > maxProvisionedNameRunes || hasOtherCategory(presented) {
		s.audit("LDAP_LOGIN_REJECTED", "user", username, "reason", "unsafe_username")
		return Identity{}, errAuthFailed
	}
	now := s.now()
	id := Identity{Provider: s.Provider, Subject: entry.Subject, DirectoryUsername: username,
		DistinguishedName: entry.DN, CreatedAt: now, LastVerifiedAt: now}
	err := s.DB.Write(ctx, func(tx *store.Tx) error {
		ok, err := s.Accounts.BreakGlassAdminTx(ctx, tx)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: a local break-glass administrator is required", ErrRejected)
		}
		if id.UserID, err = s.Accounts.ProvisionTx(ctx, tx, username, string(auth.ProviderLDAP)); err != nil {
			return err
		}
		id.ID, err = insertIdentityTx(ctx, tx, id)
		return err
	})
	switch {
	case err == nil:
		s.audit("LDAP_USER_AUTO_PROVISIONED", "user", username, "provider", s.Provider)
		return id, nil
	case errors.Is(err, ErrRejected), fault.Is(err, fault.Conflict):
		return Identity{}, errAuthFailed
	}
	// The identity may have been provisioned by a concurrent sign-in.
	if linked, found, lerr := s.linkedIdentity(ctx, entry); lerr == nil && found {
		return linked, nil
	}
	s.audit("LDAP_AUTO_PROVISION_STORAGE_FAILED", "user", username, "provider", s.Provider)
	return Identity{}, fault.Wrap(fault.Unavailable, err, messageOf(errUnavailable))
}

// hasOtherCategory reports a character whose Unicode general category is
// C (control, format, surrogate, private use, unassigned), as
// unicodedata.category(c).startswith('C') does. Invalid UTF-8 counts too.
func hasOtherCategory(s string) bool {
	if !utf8.ValidString(s) {
		return true
	}
	for _, r := range s {
		if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Co, unicode.Cs) ||
			!unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S, unicode.Z) {
			return true
		}
	}
	return false
}
