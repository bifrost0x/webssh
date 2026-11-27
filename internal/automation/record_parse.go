package automation

import (
	"encoding/json/jsontext"
	"errors"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/bifrost0x/webssh/internal/pyjson"
)

// errInvalidRecord is a stored run the Python release would refuse to
// load (_read_history).
var errInvalidRecord = errors.New("automation: invalid run record")

func names(members []pyjson.Member) []string {
	out := make([]string, len(members))
	for i, m := range members {
		out[i] = m.Name
	}
	return out
}

func sameSet(have []string, want ...string) bool {
	if len(have) != len(want) {
		return false
	}
	for _, w := range want {
		if !slices.Contains(have, w) {
			return false
		}
	}
	return true
}

func member(members []pyjson.Member, name string) jsontext.Value {
	for _, m := range members {
		if m.Name == name {
			return m.Value
		}
	}
	return nil
}

// bounded is bounded() of _read_history: a string of at most maximum
// UTF-8 bytes, or null where optional.
func bounded(v jsontext.Value, maximum int, optional bool) (*string, bool) {
	if v.Kind() == 'n' {
		return nil, optional
	}
	s, ok := pyString(v)
	if !ok || len(s) > maximum {
		return nil, false
	}
	return &s, true
}

func statusOf(v jsontext.Value) (string, bool) {
	s, ok := pyString(v)
	return s, ok && knownStatus(s)
}

// ParseRun reads one stored run as _read_history validates it.
func ParseRun(v jsontext.Value) (Run, error) {
	m, ok := pyjson.Members(v)
	if !ok {
		return Run{}, errInvalidRecord
	}
	keys := names(m)
	base := slices.DeleteFunc(slices.Clone(keys), func(k string) bool {
		return k == "runbook_id" || k == "schedule_id" || k == "claim_id"
	})
	r := Run{order: keys}
	switch {
	case sameSet(base, "id", "name", "created_at", "status", "targets"):
	case sameSet(base, "id", "name", "created_at", "finished_at", "status", "targets"):
		r.Finished = true
	default:
		return Run{}, errInvalidRecord
	}
	for name, max := range map[string]int{"runbook_id": 64, "schedule_id": 36, "claim_id": 64} {
		raw := member(m, name)
		if raw == nil {
			continue
		}
		s, ok := bounded(raw, max, false)
		if !ok || *s == "" {
			return Run{}, errInvalidRecord
		}
		switch name {
		case "runbook_id":
			r.RunbookID = s
		case "schedule_id":
			r.ScheduleID = s
		default:
			r.ClaimID = s
		}
	}
	id, ok1 := bounded(member(m, "id"), 64, false)
	name, ok2 := bounded(member(m, "name"), 128, false)
	created, ok3 := bounded(member(m, "created_at"), 64, false)
	status, ok4 := statusOf(member(m, "status"))
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return Run{}, errInvalidRecord
	}
	r.ID, r.Name, r.CreatedAt, r.Status = *id, *name, *created, status
	if r.Finished {
		f, ok := bounded(member(m, "finished_at"), 64, true)
		if !ok {
			return Run{}, errInvalidRecord
		}
		r.FinishedAt = f
	}
	items, ok := pyjson.Items(member(m, "targets"))
	if !ok || len(items) < 1 || len(items) > MaxRunTargets {
		return Run{}, errInvalidRecord
	}
	for _, item := range items {
		t, err := parseTarget(item)
		if err != nil {
			return Run{}, err
		}
		r.Targets = append(r.Targets, t)
	}
	if r.outputBytes() > RunOutputBytes {
		return Run{}, errInvalidRecord
	}
	return r, nil
}

func parseTarget(v jsontext.Value) (Target, error) {
	m, ok := pyjson.Members(v)
	if !ok || !sameSet(names(m), targetOrder...) {
		return Target{}, errInvalidRecord
	}
	t := Target{order: names(m)}
	reason, ok := bounded(member(m, "reason"), 64, true)
	if !ok || (reason != nil && !slices.Contains(connectionReasons, *reason)) {
		return Target{}, errInvalidRecord
	}
	t.Reason = reason
	fields := []*string{&t.ID, &t.Name, &t.Host, &t.Username}
	for i, name := range []string{"id", "name", "host", "username"} {
		s, ok := bounded(member(m, name), 512, false)
		if !ok {
			return Target{}, errInvalidRecord
		}
		*fields[i] = *s
	}
	group, ok := bounded(member(m, "group"), 512, true)
	if !ok {
		return Target{}, errInvalidRecord
	}
	t.Group = group
	port, isInt := pyInt(member(m, "port"))
	status, okStatus := statusOf(member(m, "status"))
	if !isInt || port < 1 || port > 65535 || !okStatus {
		return Target{}, errInvalidRecord
	}
	t.Port, t.Status = port, status
	items, ok := pyjson.Items(member(m, "steps"))
	if !ok || len(items) < 1 || len(items) > MaxSteps {
		return Target{}, errInvalidRecord
	}
	for _, item := range items {
		s, err := parseStep(item)
		if err != nil {
			return Target{}, err
		}
		t.Steps = append(t.Steps, s)
	}
	return t, nil
}

func parseStep(v jsontext.Value) (StepResult, error) {
	m, ok := pyjson.Members(v)
	if !ok {
		return StepResult{}, errInvalidRecord
	}
	keys := names(m)
	s := StepResult{order: keys}
	switch {
	case sameSet(keys, "name", "status", "exit_code", "duration"):
	case sameSet(keys, stepOrder...):
		s.Detailed = true
	default:
		return StepResult{}, errInvalidRecord
	}
	name, ok1 := bounded(member(m, "name"), MaxNameBytes, false)
	status, ok2 := statusOf(member(m, "status"))
	if !ok1 || !ok2 {
		return StepResult{}, errInvalidRecord
	}
	s.Name, s.Status = *name, status
	if exit := member(m, "exit_code"); exit.Kind() != 'n' {
		n, isInt := pyInt(exit)
		if !isInt || n < 0 || n > math.MaxUint32 {
			return StepResult{}, errInvalidRecord
		}
		s.ExitCode = &n
	}
	d := member(m, "duration")
	f, err := strconv.ParseFloat(string(d), 64)
	if d.Kind() != '0' || err != nil || math.IsInf(f, 0) || f < 0 || f > maxDuration {
		return StepResult{}, errInvalidRecord
	}
	s.Duration = pyNumber(string(d))
	if !s.Detailed {
		return s, nil
	}
	stdout, ok1 := bounded(member(m, "stdout"), StepOutputBytes, false)
	stderr, ok2 := bounded(member(m, "stderr"), StepOutputBytes, false)
	truncated, ok3 := pyBool(member(m, "output_truncated"))
	reason, ok4 := bounded(member(m, "reason"), 64, true)
	if !ok1 || !ok2 || !ok3 || !ok4 || len(*stdout)+len(*stderr) > StepOutputBytes ||
		(reason != nil && !slices.Contains(stepReasons, *reason)) {
		return StepResult{}, errInvalidRecord
	}
	s.Stdout, s.Stderr, s.Truncated, s.Reason = *stdout, *stderr, truncated, reason
	return s, nil
}

// ParseHistory reads automation-runs.json as _read_history accepts it.
func ParseHistory(doc jsontext.Value) ([]Run, error) {
	m, ok := pyjson.Members(doc)
	if !ok || !sameSet(names(m), "version", "runs") || strings.TrimSpace(string(member(m, "version"))) != "1" {
		return nil, errInvalidRecord
	}
	items, ok := pyjson.Items(member(m, "runs"))
	if !ok || len(items) > MaxRuns {
		return nil, errInvalidRecord
	}
	runs := make([]Run, 0, len(items))
	for _, item := range items {
		r, err := ParseRun(item)
		if err != nil {
			return nil, err
		}
		runs = append(runs, r)
	}
	return runs, nil
}
