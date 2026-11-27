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

// HerdrOverview decides the Herdr overview of a saved host of owner from
// the switch herdr_enabled and the host's option, read at the moment of
// the call (overview_allowed). A host that does not exist or belongs to
// another user, and any failure to read, is no grant. cmd/webssh provides
// the same decision the terminal uses (terminal.HerdrGrants).
type HerdrOverview interface {
	Overview(ctx context.Context, owner int64, profileID string) bool
}

// StepUpHeader carries the step-up grant of a request.
const StepUpHeader = "X-WebSSH-Step-Up"
