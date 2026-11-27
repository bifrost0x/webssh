# M2 contracts: automation runs (AU1)

This document is the contract part of the automation package
(`internal/automation`, M2 plan, AU1). It extends
[m2-contracts.md](m2-contracts.md); the rules of "How contracts are
fixed" in [m1-contracts.md](m1-contracts.md) apply unchanged. The tables
below are joined with those of the other contract documents by
`internal/architecture`.

### Step-up actions (automation)

| Action | Used by |
|---|---|
| `automation.run` | `internal/automation` |

`automation.run` is in the audience of every signed-in account
(`internal/auth/stepup/audience.go`). The target is the token of the
review intent; the automation checks that the intent belongs to the user
and the session and that the typed confirmation matches before it
consumes the grant. The page asks for it as in the Python release
(`static/js/automation.js`). The schedules add `automation.schedule`
(AU2).

### Store owner

`automation` (tables `automation_runbooks`, `automation_runbook_steps`,
`automation_runs`, schema version 1). The schedules (AU2) add their tables
to the same owner as version 2 in `internal/automation/schema.go`.

### Saved-password binding

`(*vault.Service).Binding(ctx, userID, resourceID, t) (Status, token,
error)` (`internal/vault/cred_binding.go`) is `credential_status` and
`generations` of the Python release in one call: the state of the
assignment for the target `t` the caller reviewed (`ready`, `changed`,
`missing`, `disabled`) and, when ready, an opaque token that changes with
every new or changed assignment, a replaced password and every change of
the saved-password switch. Runs and schedules keep the token of the
review and stop when it changes. It reveals nothing about the secret.

### Run interface (for the schedules)

Compiled in `internal/automation/scheduled.go` and `review.go`:

```go
func (s *Service) Freeze(ctx, userID int64, runbookID string, profileIDs, groups []string) (Reviewed, error)
func (s *Service) StartScheduled(ctx, sc Scheduled) (Run, error)   // failures are *NotDispatched
func (s *Service) Runbook(ctx, userID int64, id string) (Runbook, error)
func (s *Service) Cancel(ctx, userID int64, runID string, manualOnly bool) error
func (s *Service) SetSchedules(r ScheduleRuns)
func (b Runbook) Digest() string                                  // digest() of automation_store.py

type Scheduled struct {
	UserID              int64
	ScheduleID, ClaimID string
	Reviewed            Reviewed
	Check  func(ctx context.Context) error            // the schedule's grant; stops the run
	Finish func(ctx context.Context, status string) error
}
type ScheduleRuns interface {
	CancelRun(ctx context.Context, userID int64, scheduleID, claimID string) error
}
```

- `Freeze` is the review without an intent: runbook, targets with their
  jump hosts, trusted host keys, bound saved passwords and readable keys,
  with the same errors as the review route (`host_key_required` names the
  hosts).
- `StartScheduled` validates the frozen run against the current runbook,
  hosts, keys and password bindings, then dispatches it like a manual run
  (one per user, four in all, the `background_job` quota). The record
  carries `schedule_id` and `claim_id`; `Finish` gets the final status
  once it is stored.
- `Cancel` of a scheduled run that is not active in this process calls
  `CancelRun`, so its claim settles.
