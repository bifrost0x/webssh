package ldap

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// Messages of ldap_routes.py.
var (
	errUserNotFound    = fault.New(fault.NotFound, "User not found")
	errAdminTarget     = fault.New(fault.InvalidRequest, "Administrator accounts must remain local break-glass accounts")
	errConfirmation    = fault.New(fault.InvalidRequest, "Target confirmation does not match")
	errDirectoryName   = fault.New(fault.InvalidRequest, "Directory username is required")
	errAlreadyLinked   = fault.New(fault.Conflict, "User already has an LDAP identity")
	errGitHubManaged   = fault.New(fault.Conflict, "LDAP cannot be linked to a GitHub-managed account")
	errNotUnique       = fault.New(fault.InvalidRequest, "Directory identity was not found uniquely")
	errDirectoryDown   = fault.New(fault.Unavailable, "Directory is temporarily unavailable")
	errIdentityTaken   = fault.New(fault.Conflict, "LDAP identity is already linked")
	errStorage         = fault.New(fault.Unavailable, "LDAP identity storage is temporarily unavailable")
	errIdentityMissing = fault.New(fault.NotFound, "LDAP identity not found")
	errNewPassword     = fault.New(fault.InvalidRequest, "New password is required")
	errConfigAdmin     = fault.New(fault.Conflict, "This account is listed in ADMIN_USERS. Remove it from ADMIN_USERS before converting it to a local account.")
)

// LinkRequest is the body of POST /admin/api/users/{id}/ldap-link.
type LinkRequest struct {
	ConfirmUsername   string
	DirectoryUsername string
	// Valid is false when directory_username is not a JSON string.
	Valid bool
	// Malformed is the error of a body that is no JSON object or too
	// large; it is answered after the grant was consumed, as the Python
	// decorator consumed it first.
	Malformed error
}

func storageFault(err error) error {
	if _, ok := fault.From(err); ok {
		return err
	}
	return fault.Wrap(fault.Unavailable, err, messageOf(errStorage))
}

// AdminLink binds the directory entry of a name to a local account
// (link_ldap_identity). The grant of ldap.link for the account id is
// consumed first. The account becomes LDAP-managed: its local password is
// replaced by an unusable one, its OIDC identities are removed, its auth
// generation is raised and its sessions end.
func (s *Service) AdminLink(ctx context.Context, p principal.Principal, userID int64, req LinkRequest, grant string) (int64, error) {
	if err := s.StepUp.Consume(ctx, p, principal.ActionLDAPLink, strconv.FormatInt(userID, 10), grant); err != nil {
		return 0, err
	}
	if req.Malformed != nil {
		return 0, req.Malformed
	}
	target, err := s.account(ctx, userID)
	if err != nil {
		return 0, err
	}
	name := pyStrip(req.DirectoryUsername)
	switch {
	case target.IsAdmin:
		return 0, errAdminTarget
	case req.ConfirmUsername != target.Username:
		return 0, errConfirmation
	case !req.Valid || name == "" || utf8.RuneCountInString(name) > maxUsernameRunes:
		return 0, errDirectoryName
	}
	if _, found, err := s.IdentityOf(ctx, userID); err != nil {
		return 0, err
	} else if found {
		return 0, errAlreadyLinked
	}
	if target.Managed == string(auth.ProviderGitHub) {
		return 0, errGitHubManaged
	}
	entry, err := s.Directory.Lookup(ctx, name)
	switch {
	case errors.Is(err, ErrRejected):
		return 0, errNotUnique
	case err != nil:
		s.audit("LDAP_LINK_UNAVAILABLE", "admin", p.Username, "user", target.Username, "error", errorKind(err))
		return 0, fault.Wrap(fault.Unavailable, err, messageOf(errDirectoryDown))
	}
	now := s.now()
	id := Identity{UserID: userID, Provider: s.Provider, Subject: entry.Subject, DirectoryUsername: name,
		DistinguishedName: entry.DN, CreatedAt: now, LastVerifiedAt: now}
	var revs []principal.Revocation
	err = s.DB.Write(ctx, func(tx *store.Tx) error {
		if _, err := identityBySubjectTx(ctx, tx, id.Provider, id.Subject); err == nil {
			return errIdentityTaken
		} else if !errors.Is(err, errNoIdentity) {
			return err
		}
		if _, err := identityOfTx(ctx, tx, userID); err == nil {
			return errAlreadyLinked
		} else if !errors.Is(err, errNoIdentity) {
			return err
		}
		if err := s.Accounts.AdoptTx(ctx, tx, userID, string(auth.ProviderLDAP)); err != nil {
			return err
		}
		if s.OIDC != nil {
			if err := s.OIDC.RemoveAllTx(ctx, tx, userID); err != nil {
				return err
			}
		}
		var err error
		if id.ID, err = insertIdentityTx(ctx, tx, id); err != nil {
			return err
		}
		if err := checkedTx(ctx, tx, userID, now); err != nil {
			return err
		}
		revs, err = s.Sessions.RevokeAccountTx(ctx, tx, userID, principal.ReasonPasswordChanged)
		return err
	})
	if err != nil {
		s.audit("LDAP_IDENTITY_STORAGE_FAILED", "admin", p.Username, "user", target.Username)
		return 0, storageFault(err)
	}
	s.Sessions.Publish(revs)
	s.audit("LDAP_IDENTITY_LINKED", "admin", p.Username, "user", target.Username, "provider", id.Provider)
	return id.ID, nil
}

// UnlinkRequest is the body of DELETE …/ldap-identities/{identity_id}.
type UnlinkRequest struct {
	ConfirmUsername string
	NewPassword     string
	// HasPassword is false when new_password is not a JSON string.
	HasPassword bool
	// Malformed is as in LinkRequest.
	Malformed error
}

// AdminUnlink removes an LDAP identity from its account and makes the account
// local again with a new password (unlink_ldap_identity). The grant of
// ldap.unlink for "<user id>:<identity id>" is consumed first. Accounts
// listed in ADMIN_USERS keep their identity.
func (s *Service) AdminUnlink(ctx context.Context, p principal.Principal, userID, identityID int64, req UnlinkRequest, grant string) error {
	target := strconv.FormatInt(userID, 10) + ":" + strconv.FormatInt(identityID, 10)
	if err := s.StepUp.Consume(ctx, p, principal.ActionLDAPUnlink, target, grant); err != nil {
		return err
	}
	if req.Malformed != nil {
		return req.Malformed
	}
	acc, err := s.account(ctx, userID)
	if err != nil {
		return err
	}
	if req.ConfirmUsername != acc.Username {
		return errConfirmation
	}
	id, found, err := s.IdentityOf(ctx, userID)
	if err != nil {
		return err
	}
	if !found || id.ID != identityID {
		return errIdentityMissing
	}
	if s.Admins != nil && s.Admins(acc.Username) {
		s.audit("LDAP_IDENTITY_UNLINK_REJECTED", "admin", p.Username, "user", acc.Username, "reason", "listed_in_admin_users")
		return errConfigAdmin
	}
	if !req.HasPassword {
		return errNewPassword
	}
	if msg := s.Passwords.ValidateNew(req.NewPassword); msg != "" {
		return fault.New(fault.InvalidValue, "New p"+strings.TrimPrefix(msg, "P"))
	}
	hash, err := s.Passwords.Hash(ctx, req.NewPassword)
	if err != nil {
		return err
	}
	var revs []principal.Revocation
	err = s.DB.Write(ctx, func(tx *store.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM authldap_identities WHERE id = ? AND user_id = ?`, identityID, userID)
		if err != nil {
			return fmt.Errorf("ldap: delete identity: %w", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return errIdentityMissing
		}
		if err := forgetTx(ctx, tx, userID); err != nil {
			return err
		}
		if err := s.Accounts.ReleaseTx(ctx, tx, userID, hash); err != nil {
			return err
		}
		revs, err = s.Sessions.RevokeAccountTx(ctx, tx, userID, principal.ReasonPasswordChanged)
		return err
	})
	if err != nil {
		s.audit("LDAP_IDENTITY_STORAGE_FAILED", "admin", p.Username, "user", acc.Username)
		return storageFault(err)
	}
	s.Sessions.Publish(revs)
	s.audit("LDAP_IDENTITY_UNLINKED", "admin", p.Username, "user", acc.Username, "provider", id.Provider)
	return nil
}

func (s *Service) account(ctx context.Context, userID int64) (Account, error) {
	var acc Account
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		acc, err = s.Accounts.GetTx(ctx, tx, userID)
		return err
	})
	if fault.Is(err, fault.NotFound) {
		return Account{}, errUserNotFound
	}
	if err != nil {
		return Account{}, fault.Wrap(fault.StorageError, err, "")
	}
	return acc, nil
}

// Status probes the directory with the service account
// (GET /admin/api/ldap/status).
func (s *Service) Status(ctx context.Context, p principal.Principal) (ready bool, transport string) {
	err := s.Directory.Probe(ctx)
	if err != nil {
		s.audit("LDAP_READINESS_FAILED", "admin", p.Username, "error", errorKind(err))
	}
	return err == nil, s.Directory.Transport()
}
