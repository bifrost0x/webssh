package stepup

import (
	"context"
	"fmt"
	"strings"

	"github.com/bifrost0x/webssh/internal/store"
)

// RevokeAdminTx removes the step-up grants and intents of userID that
// confirm an administrator action, inside the caller's write transaction.
// Administrator routes check the flag on every request, so a grant is
// useless while the account is not an administrator; removing it keeps a
// grant from before a demotion from serving after a later promotion
// (RS8-R01). The grants of the account's own actions stay.
func (s *Service) RevokeAdminTx(ctx context.Context, tx *store.Tx, userID int64) error {
	actions := make([]any, 0, len(adminActions)+2)
	actions = append(actions, userID)
	for _, a := range adminActions {
		actions = append(actions, string(a))
	}
	in := "(" + strings.TrimSuffix(strings.Repeat("?, ", len(adminActions)), ", ") + ")"
	if _, err := tx.ExecContext(ctx, `DELETE FROM stepup_grants WHERE user_id = ? AND action IN `+in, actions...); err != nil {
		return fmt.Errorf("stepup: drop administrator grants: %w", err)
	}
	actions = append(actions, ChannelAdmin)
	if _, err := tx.ExecContext(ctx, `DELETE FROM stepup_intents WHERE user_id = ? AND (action IN `+in+` OR channel = ?)`, actions...); err != nil {
		return fmt.Errorf("stepup: drop administrator intents: %w", err)
	}
	return nil
}
