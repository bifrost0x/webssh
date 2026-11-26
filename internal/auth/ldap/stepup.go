package ldap

import (
	"context"
	"fmt"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
)

// maxStepUpPassword bounds the directory password of a step-up in bytes
// (ldap_step_up).
const maxStepUpPassword = 4096

// StepUpLinked reports whether the LDAP step-up proof can be offered to
// the account: LDAP is active and the account has an LDAP identity.
func (s *Service) StepUpLinked(ctx context.Context, userID int64) (bool, error) {
	if !s.active(ctx) {
		return false, nil
	}
	_, found, err := s.IdentityOf(ctx, userID)
	return found, err
}

// VerifyStepUp proves the account's directory password again
// (POST /api/account/step-up/ldap): the stored directory name must still
// resolve to the same binding and the user's bind must succeed. A wrong
// password or a changed binding is false; a directory without a verdict
// is fault.Unavailable. On success the entry's DN and the verification
// time are recorded.
func (s *Service) VerifyStepUp(ctx context.Context, userID int64, password string) (bool, error) {
	if password == "" || len(password) > maxStepUpPassword || !s.active(ctx) {
		return false, nil
	}
	id, found, err := s.IdentityOf(ctx, userID)
	if err != nil || !found {
		return false, err
	}
	entry, err := s.Directory.Lookup(ctx, id.DirectoryUsername)
	if err != nil {
		if fault.Is(classify(err, errDirectoryDown), fault.AuthFailed) {
			return false, nil
		}
		return false, fault.Wrap(fault.Unavailable, err, messageOf(errDirectoryDown))
	}
	if id.Provider != s.Provider || entry.Subject != id.Subject {
		return false, nil
	}
	ok, err := s.Directory.VerifyPassword(ctx, entry.DN, password)
	if err != nil {
		return false, fault.Wrap(fault.Unavailable, err, messageOf(errDirectoryDown))
	}
	if !ok {
		return false, nil
	}
	err = s.DB.Write(ctx, func(tx *store.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE authldap_identities SET distinguished_name = ?, last_verified_us = ? WHERE id = ?`,
			entry.DN, s.now().UnixMicro(), id.ID)
		if err != nil {
			return fmt.Errorf("ldap: record step-up: %w", err)
		}
		return nil
	})
	if err != nil {
		return false, fault.Wrap(fault.StorageError, err, "")
	}
	return true, nil
}
