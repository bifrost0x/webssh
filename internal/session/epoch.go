package session

import (
	"context"

	"github.com/bifrost0x/webssh/internal/store"
)

// Epoch returns the installation's sign-out generation, which RevokeAll
// replaces. Approved schedules are bound to it: a global sign-out ends
// their approval, as rotating session_epoch did in the Python release.
func (s *Service) Epoch(ctx context.Context) (string, error) {
	var epoch string
	err := s.db.Read(ctx, func(tx *store.Tx) error {
		var err error
		epoch, err = currentEpoch(ctx, tx)
		return err
	})
	return epoch, err
}

// EpochTx is Epoch inside a transaction (the migration binds the
// approvals it writes to the generation of the new database).
func EpochTx(ctx context.Context, tx *store.Tx) (string, error) {
	return currentEpoch(ctx, tx)
}
