// Package operations holds diagnostics, the support report and the
// security feature gates. M1 builds the feature gates and their impact
// preview only.
package operations

import (
	"context"

	"github.com/bifrost0x/webssh/internal/principal"
)

// StepUp consumes a step-up grant for one action on one target (provided
// by internal/auth/stepup). It fails with fault.StepUpRequired when the
// grant is missing, expired, already used or bound to another user,
// session, action or target; the caller then refuses the operation.
type StepUp interface {
	Consume(ctx context.Context, p principal.Principal, action principal.Action, target, grant string) error
}
