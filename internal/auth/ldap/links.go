package ldap

import (
	"context"
	"errors"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
)

var _ auth.IdentityLinks = (*Service)(nil)

func linked(id Identity) auth.LinkedIdentity {
	return auth.LinkedIdentity{ID: id.ID, UserID: id.UserID, Provider: auth.ProviderLDAP, Issuer: id.Provider,
		Subject: id.Subject, Username: id.DirectoryUsername, CreatedAt: id.CreatedAt, LastVerifiedAt: id.LastVerifiedAt}
}

// Account implements auth.IdentityLinks: the account of (provider,
// subject), or fault.NotFound.
func (s *Service) Account(ctx context.Context, id auth.Identity) (int64, error) {
	var row Identity
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		row, err = identityBySubjectTx(ctx, tx, id.Issuer, id.Subject)
		return err
	})
	if errors.Is(err, errNoIdentity) || id.Provider != auth.ProviderLDAP {
		return 0, fault.New(fault.NotFound, "")
	}
	if err != nil {
		return 0, fault.Wrap(fault.StorageError, err, "")
	}
	return row.UserID, nil
}

// Provision implements auth.IdentityLinks with the rules of
// LDAP_AUTO_PROVISION; the identity must name the entry's DN.
func (s *Service) Provision(ctx context.Context, id auth.Identity) (int64, error) {
	if !s.AutoProvision || id.Provider != auth.ProviderLDAP || id.Issuer != s.Provider {
		return 0, fault.New(fault.Forbidden, "")
	}
	row, err := s.provision(ctx, pyStrip(id.Username), id.Username, Entry{Subject: id.Subject, DN: id.DistinguishedName})
	if err != nil {
		return 0, err
	}
	return row.UserID, nil
}

// LinkTx implements auth.IdentityLinks inside the caller's transaction;
// the account's other state is the caller's (AdminLink does the whole
// administrator flow).
func (s *Service) LinkTx(ctx context.Context, tx *store.Tx, userID int64, id auth.Identity) (auth.LinkedIdentity, error) {
	if id.Provider != auth.ProviderLDAP || id.Subject == "" {
		return auth.LinkedIdentity{}, fault.New(fault.InvalidRequest, "")
	}
	if _, err := identityBySubjectTx(ctx, tx, id.Issuer, id.Subject); err == nil {
		return auth.LinkedIdentity{}, fault.New(fault.Conflict, "")
	}
	if _, err := identityOfTx(ctx, tx, userID); err == nil {
		return auth.LinkedIdentity{}, fault.New(fault.Conflict, "")
	}
	now := s.now()
	row := Identity{UserID: userID, Provider: id.Issuer, Subject: id.Subject, DirectoryUsername: id.Username,
		DistinguishedName: id.DistinguishedName, CreatedAt: now, LastVerifiedAt: now}
	var err error
	if row.ID, err = insertIdentityTx(ctx, tx, row); err != nil {
		return auth.LinkedIdentity{}, err
	}
	return linked(row), nil
}

// Unlink implements auth.IdentityLinks: it removes the identity row only.
// The administrator route uses Service.AdminUnlink, which also gives the
// account a new local password.
func (s *Service) Unlink(ctx context.Context, userID, identityID int64) error {
	return s.DB.Write(ctx, func(tx *store.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM authldap_identities WHERE id = ? AND user_id = ?`, identityID, userID)
		if err != nil {
			return fault.Wrap(fault.StorageError, err, "")
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return fault.New(fault.NotFound, "")
		}
		return forgetTx(ctx, tx, userID)
	})
}

// List implements auth.IdentityLinks.
func (s *Service) List(ctx context.Context, userID int64) ([]auth.LinkedIdentity, error) {
	id, found, err := s.IdentityOf(ctx, userID)
	if err != nil || !found {
		return nil, err
	}
	return []auth.LinkedIdentity{linked(id)}, nil
}
