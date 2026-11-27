package automation

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

// Limits of the schedules (app/automation_schedule.py).
const (
	// MaxSchedules is the number of schedules per account.
	MaxSchedules = 50
	// ScheduleTickInterval is how often due schedules are dispatched (the
	// cleanup loop of app/automation_service.py).
	ScheduleTickInterval = 5 * time.Second
	// scheduleBatch bounds the due schedules of one tick; the oldest
	// slots come first.
	scheduleBatch = 200
	// missedAfter: a slot found this late is recorded as missed, not run.
	missedAfter = 60 * time.Second
	// staleClaim: a claim older than this belongs to a run that cannot
	// still be going (the run deadline of 30 minutes plus a minute). Its
	// schedule is paused with an unknown outcome.
	staleClaim = 1860 * time.Second
	// maxScheduleIDBytes bounds a schedule id in a request.
	maxScheduleIDBytes = 36
)

// Last statuses of a schedule as the page shows them.
const (
	StatusWaiting     = "waiting"
	StatusPaused      = "paused"
	StatusRunning     = "running"
	StatusMissed      = "missed"
	StatusOverlap     = "overlap"
	StatusSkipped     = "skipped"
	StatusNeedsReview = "needs_review"
	StatusUnknown     = "unknown"
)

// Snapshot is a reviewed run as the run side of automation freezes it:
// the runbook as stored, the targets as resources (each saved host with
// its route_fingerprint and, for a jump host, the frozen hop in "route"),
// and the SHA-256 of every decrypted key the run will use, by resource id.
// A schedule keeps it as its approval.
type Snapshot struct {
	Book       jsontext.Value
	Targets    []jsontext.Value
	KeyDigests map[string]string
}

// ScheduleWorkflows is the run side of automation (runbooks, inventory,
// host keys, key digests and the run engine), provided by the runbook
// part of this package (AU1). Schedules freeze its review and hand the
// frozen run back to it without a signed-in session.
type ScheduleWorkflows interface {
	// Review freezes the run the page asks for (the members runbook_id,
	// profile_ids and groups of the request body), with the checks of a
	// manual review: the runbook exists, the targets are supported and
	// have a verified host key, the keys can be read.
	Review(ctx context.Context, p principal.Principal, request jsontext.Value) (Snapshot, error)
	// Current fails with fault.PreviewChanged unless the runbook is still
	// stored as frozen, every target and hop still has its frozen
	// fingerprint and every key its frozen digest.
	Current(ctx context.Context, userID int64, s Snapshot) error
	// PrepareManual registers a reviewed manual run of the frozen
	// snapshot for the session (preview-run) and returns the answer of
	// the preview: intent, runbook, targets, confirmation, expires_in.
	// check is the schedule's own validation; the run side calls it
	// when the run starts and while it runs.
	PrepareManual(ctx context.Context, p principal.Principal, s Snapshot, check func(context.Context) error) (jsontext.Value, error)
	// StartScheduled dispatches an approved run. A *NotDispatchedError
	// says nothing reached any target; any other error leaves the
	// outcome open and the schedule is paused with an unknown status.
	StartScheduled(ctx context.Context, run ScheduledRun) error
}

// ScheduledRun is a run started by a schedule, without a session.
type ScheduledRun struct {
	UserID     int64
	ScheduleID string
	ClaimID    string
	Snapshot   Snapshot
	// Check validates the approval again: the account, the policy, the
	// schedule's revision and claim, the frozen targets and keys and the
	// binding to the saved passwords. The run side calls it before the
	// run, before every target and step, and stops when it fails.
	Check func(ctx context.Context) error
	// Password returns the saved password of a password hop for this run;
	// it checks the binding first. The caller clears the secret.
	Password func(ctx context.Context, hop jsontext.Value) ([]byte, error)
	// Finish records the final status of the run; the run side calls it
	// once after a dispatched run ended.
	Finish func(ctx context.Context, status string)
}

// NotDispatchedError reports that a run was definitely not started.
// Codes busy, unavailable and storage_limit only skip the slot; any
// other code needs a new review of the schedule.
type NotDispatchedError struct{ Code fault.Code }

func (e *NotDispatchedError) Error() string {
	return "automation: run not dispatched: " + string(e.Code)
}

func transient(err error) (notDispatched, skip bool) {
	var nd *NotDispatchedError
	if !errors.As(err, &nd) {
		return false, false
	}
	switch nd.Code {
	case fault.Busy, fault.Unavailable, fault.StorageLimit:
		return true, true
	}
	return true, false
}

// AccountBinding is what an approval binds to the account: its
// incarnation, its sign-in generation (raised by a password change or a
// lock) and the installation's sign-out generation. Locked accounts never
// run.
type AccountBinding struct {
	Incarnation    string
	AuthGeneration int64
	Epoch          string
	Locked         bool
}

// ScheduleAccounts returns the binding of an account (provided over
// internal/accounts and internal/session). A deleted account is
// fault.NotFound.
type ScheduleAccounts interface {
	ScheduleAccount(ctx context.Context, userID int64) (AccountBinding, error)
}

// SchedulePolicy is the administrator switch of automation and its
// revision (automation_enabled, automation_enabled_revision).
type SchedulePolicy interface {
	AutomationPolicy(ctx context.Context) (enabled bool, revision string, err error)
}

// SchedulePasswords binds a schedule to the saved passwords of its
// password hops (provided by internal/vault: ScheduleBinding and
// Password).
type SchedulePasswords interface {
	ScheduleBinding(ctx context.Context, userID int64, hops []jsontext.Value) (jsontext.Value, error)
	SchedulePassword(ctx context.Context, userID int64, hop jsontext.Value) ([]byte, error)
}

// ScheduleStepUp consumes a step-up grant (provided by
// internal/auth/stepup).
type ScheduleStepUp interface {
	Consume(ctx context.Context, p principal.Principal, action principal.Action, target, grant string) error
}

// ScheduleAudit records security events (provided by internal/audit).
type ScheduleAudit interface {
	Security(event string, kv ...any)
}
