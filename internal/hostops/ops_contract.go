package hostops

import (
	"context"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/ssh/remotecmd"
)

// Live is a connected terminal session of the caller as server
// operations, insights, the inventory and Herdr use it (internal/terminal
// through cmd/webssh). Exec runs commands on a separate channel of the
// session's connection. Done is closed when the session ends and
// identifies it: a later session with the same ID is another session.
type Live struct {
	Exec      remotecmd.Executor
	Host      string
	Port      int
	Username  string
	ProfileID string
	Herdr     bool // the Herdr overview granted at connect
	UseHerdr  bool
	Done      <-chan struct{}
}

// Sessions finds a connected session of owner; sessions of other users
// and ended sessions are not found.
type Sessions interface {
	Live(owner int64, sessionID string) (Live, bool)
}

// StepUp consumes a step-up grant for one action on one target (provided
// by internal/auth/stepup); it fails with fault.StepUpRequired when the
// grant is missing or does not match.
type StepUp interface {
	Consume(ctx context.Context, p principal.Principal, action principal.Action, target, grant string) error
}

// Auditor writes security events to the audit log (internal/audit).
type Auditor interface {
	Security(event string, kv ...any)
}

// Switches reads the runtime switches of the integrations
// (server_operations_enabled with SERVER_OPERATIONS_ENABLED, herdr_enabled)
// from internal/settings. A failure to read one counts as off.
type Switches interface {
	ServerOperationsEnabled(ctx context.Context) bool
	HerdrEnabled(ctx context.Context) bool
}

// Profiles reports the Herdr options of a saved host of owner
// (internal/hosts): herdr turns on the overview, useHerdr the session
// mode. A host that does not exist or belongs to another user has
// neither.
type Profiles interface {
	HerdrOptions(ctx context.Context, owner int64, profileID string) (herdr, useHerdr bool, err error)
}

// StepUpHeader carries the step-up grant of a request.
const StepUpHeader = "X-WebSSH-Step-Up"
