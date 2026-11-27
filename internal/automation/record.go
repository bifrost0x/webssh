package automation

import (
	"encoding/json/jsontext"
	"math"
	"slices"
	"strconv"

	"github.com/bifrost0x/webssh/internal/pyjson"
)

// Limits of the run history (automation_service.py, automation_transport.py).
const (
	MaxRuns         = 50
	MaxRunTargets   = 50
	StepOutputBytes = 8 << 10
	RunOutputBytes  = 64 << 10
	maxDuration     = 1801
)

// Outcomes of runs, targets and steps.
const (
	StatusQueued    = "queued"
	StatusRunning   = "running"
	StatusSucceeded = "succeeded"
	StatusFailed    = "failed"
	StatusUnknown   = "unknown"
	StatusCancelled = "cancelled"
	StatusSkipped   = "skipped"
)

func terminal(s string) bool {
	switch s {
	case StatusSucceeded, StatusFailed, StatusUnknown, StatusCancelled, StatusSkipped:
		return true
	}
	return false
}

func knownStatus(s string) bool { return terminal(s) || s == StatusQueued || s == StatusRunning }

// connectionReasons are the reasons of a target (CONNECTION_REASONS).
var connectionReasons = []string{"host_key_required", "host_key_changed", "host_key_revoked",
	"authentication_failed", "connect_timeout", "connection_failed", "preview_changed", "key_unavailable",
	"credential_missing", "vault_locked", "run_interrupted", "tailscale_route_restricted"}

// stepReasons are the reasons of a step (STEP_REASONS).
var stepReasons = []string{"nonzero_exit", "timeout", "cancelled", "output_limit",
	"channel_lost", "acknowledgement_lost", "dispatch_failed", "run_interrupted"}

// Member orders of a record as the Python release creates it. A record
// read from storage keeps the order it was written in; members added
// later go to the end, as in a Python dict.
var (
	runOrder    = []string{"id", "runbook_id", "name", "created_at", "status", "targets", "schedule_id", "claim_id", "finished_at"}
	targetOrder = []string{"id", "name", "host", "port", "username", "group", "status", "reason", "steps"}
	stepOrder   = []string{"name", "status", "exit_code", "duration", "reason", "stdout", "stderr", "output_truncated"}
)

// Run is one record of the run history.
type Run struct {
	order      []string
	ID         string
	RunbookID  *string
	Name       string
	CreatedAt  string
	Status     string
	Targets    []Target
	ScheduleID *string
	ClaimID    *string
	// Finished reports the member finished_at; FinishedAt may still be
	// null in a stored record.
	Finished   bool
	FinishedAt *string
}

// Target is one host of a run.
type Target struct {
	order    []string
	ID       string
	Name     string
	Host     string
	Port     int64
	Username string
	Group    *string
	Status   string
	Reason   *string
	Steps    []StepResult
}

// StepResult is the outcome of one step on one host. Records of early
// releases have no output members (Detailed false).
type StepResult struct {
	order    []string
	Name     string
	Status   string
	ExitCode *int64
	// Duration is the number text Python prints for the seconds.
	Duration  string
	Detailed  bool
	Reason    *string
	Stdout    string
	Stderr    string
	Truncated bool
}

func ptr[T any](v T) *T { return &v }

func strOrNull(s *string) jsontext.Value {
	if s == nil {
		return jsontext.Value("null")
	}
	return pyjson.String(*s)
}

// ordered emits the present members in the stored order, then the rest
// in the canonical order.
func ordered(stored, canonical []string, values map[string]jsontext.Value) jsontext.Value {
	var out []pyjson.Member
	seen := map[string]bool{}
	for _, list := range [][]string{stored, canonical} {
		for _, name := range list {
			if v, ok := values[name]; ok && !seen[name] {
				seen[name] = true
				out = append(out, pyjson.Member{Name: name, Value: v})
			}
		}
	}
	return pyjson.Object(out)
}

// Value is the record as stored and sent: member order kept.
func (r *Run) Value() jsontext.Value {
	targets := make([]jsontext.Value, len(r.Targets))
	for i := range r.Targets {
		targets[i] = r.Targets[i].value()
	}
	v := map[string]jsontext.Value{
		"id": pyjson.String(r.ID), "name": pyjson.String(r.Name), "created_at": pyjson.String(r.CreatedAt),
		"status": pyjson.String(r.Status), "targets": pyjson.Array(targets),
	}
	if r.RunbookID != nil {
		v["runbook_id"] = pyjson.String(*r.RunbookID)
	}
	if r.ScheduleID != nil {
		v["schedule_id"] = pyjson.String(*r.ScheduleID)
	}
	if r.ClaimID != nil {
		v["claim_id"] = pyjson.String(*r.ClaimID)
	}
	if r.Finished {
		v["finished_at"] = strOrNull(r.FinishedAt)
	}
	return ordered(r.order, runOrder, v)
}

func (t *Target) value() jsontext.Value {
	steps := make([]jsontext.Value, len(t.Steps))
	for i := range t.Steps {
		steps[i] = t.Steps[i].value()
	}
	return ordered(t.order, targetOrder, map[string]jsontext.Value{
		"id": pyjson.String(t.ID), "name": pyjson.String(t.Name), "host": pyjson.String(t.Host),
		"port": jsontext.Value(strconv.FormatInt(t.Port, 10)), "username": pyjson.String(t.Username),
		"group": strOrNull(t.Group), "status": pyjson.String(t.Status), "reason": strOrNull(t.Reason),
		"steps": pyjson.Array(steps),
	})
}

func (s *StepResult) value() jsontext.Value {
	exit := jsontext.Value("null")
	if s.ExitCode != nil {
		exit = jsontext.Value(strconv.FormatInt(*s.ExitCode, 10))
	}
	v := map[string]jsontext.Value{
		"name": pyjson.String(s.Name), "status": pyjson.String(s.Status), "exit_code": exit,
		"duration": jsontext.Value(s.Duration),
	}
	if s.Detailed {
		v["reason"] = strOrNull(s.Reason)
		v["stdout"] = pyjson.String(s.Stdout)
		v["stderr"] = pyjson.String(s.Stderr)
		v["output_truncated"] = jsonBool(s.Truncated)
	}
	return ordered(s.order, stepOrder, v)
}

// clone returns a deep copy, so a snapshot never shares a slice with
// the running record.
func (r *Run) clone() Run {
	c := *r
	c.Targets = slices.Clone(r.Targets)
	for i := range c.Targets {
		c.Targets[i].Steps = slices.Clone(r.Targets[i].Steps)
	}
	return c
}

// outputBytes is the stdout and stderr of the run in UTF-8 bytes.
func (r *Run) outputBytes() int {
	n := 0
	for _, t := range r.Targets {
		for _, s := range t.Steps {
			n += len(s.Stdout) + len(s.Stderr)
		}
	}
	return n
}

// durationText is round(seconds, 2) as Python prints it.
func durationText(seconds float64) string {
	return pyFloat(math.Round(seconds*100) / 100)
}
