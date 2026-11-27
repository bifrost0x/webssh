package automation

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"maps"
	"slices"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/vault"
)

// Workflows returns the run side of the schedules: the review, the
// validation of an approval and the start of an approved run, over the
// runbooks, the inventory and the run engine of this Service.
//
// A Snapshot keeps the targets in the form the Python release stored in a
// schedule's grant: the resource of the saved host as the credentials
// page lists it (with route_fingerprint) and, behind a jump host, the
// jump host's resource in "route". A migrated grant has the same form, so
// both are checked the same way: every target must still have its frozen
// fingerprint (profile_fingerprint) and every key its frozen digest.
func (s *Service) Workflows() ScheduleWorkflows { return workflows{s} }

type workflows struct{ s *Service }

var _ ScheduleWorkflows = workflows{}

func (w workflows) Review(ctx context.Context, p principal.Principal, request jsontext.Value) (Snapshot, error) {
	idV, _ := pyjson.Get(request, "runbook_id")
	id, _ := pyString(idV)
	sel, err := parseSelection(request)
	if err != nil {
		return Snapshot{}, scheduleFault(err)
	}
	f, err := w.s.Freeze(ctx, p.UserID, id, sel.ProfileIDs, sel.Groups)
	if err != nil {
		return Snapshot{}, scheduleFault(err)
	}
	targets := make([]jsontext.Value, len(f.Targets))
	for i, t := range f.Targets {
		targets[i] = t.resource()
	}
	return Snapshot{Book: f.Runbook.Value(), Targets: targets, KeyDigests: f.KeyDigests}, nil
}

func (w workflows) Current(ctx context.Context, userID int64, snap Snapshot) error {
	_, err := w.reviewed(ctx, userID, snap)
	return err
}

func (w workflows) PrepareManual(ctx context.Context, p principal.Principal, snap Snapshot, check func(context.Context) error) (jsontext.Value, error) {
	f, err := w.reviewed(ctx, p.UserID, snap)
	if err != nil {
		return nil, err
	}
	out, err := w.s.remember(&review{userID: p.UserID, sessionID: p.SessionID, book: f.Runbook, targets: f.Targets,
		keyDigests: f.KeyDigests, bindings: f.Bindings, check: check})
	return out, scheduleFault(err)
}

func (w workflows) StartScheduled(ctx context.Context, run ScheduledRun) error {
	f, err := w.reviewed(ctx, run.UserID, run.Snapshot)
	if err != nil {
		if fault.CodeOf(err) == fault.StorageError {
			return &NotDispatchedError{Code: fault.Unavailable}
		}
		return &NotDispatchedError{Code: fault.CodeOf(err)}
	}
	sc := Scheduled{UserID: run.UserID, ScheduleID: run.ScheduleID, ClaimID: run.ClaimID, Reviewed: f, Check: run.Check}
	if run.Finish != nil {
		sc.Finish = func(ctx context.Context, status string) error {
			run.Finish(ctx, status)
			return nil
		}
	}
	if _, err := w.s.StartScheduled(ctx, sc); err != nil {
		if nd, ok := errors.AsType[*NotDispatched](err); ok {
			return &NotDispatchedError{Code: fault.Code(nd.Code)}
		}
		return err
	}
	return nil
}

// reviewed checks a snapshot against the current state (_validate_snapshot
// of app/automation_schedule.py without the account and policy, which
// the schedules check) and returns the run it describes: the runbook
// must be stored as frozen, every target and its jump host must have its
// frozen fingerprint, every key its frozen digest. The bindings of the
// saved passwords are today's; the schedules bind them separately.
func (w workflows) reviewed(ctx context.Context, userID int64, snap Snapshot) (Reviewed, error) {
	changed := fault.New(fault.PreviewChanged, "")
	if err := w.s.enabledSwitch(ctx); err != nil {
		return Reviewed{}, changed
	}
	idV, _ := pyjson.Get(snap.Book, "id")
	id, _ := pyString(idV)
	books, err := w.s.runbooks(ctx, userID)
	if err != nil {
		return Reviewed{}, scheduleFault(err)
	}
	i := slices.IndexFunc(books, func(b Runbook) bool { return b.ID == id })
	if i < 0 || !sameJSON(books[i].Value(), snap.Book) || len(snap.Targets) == 0 {
		return Reviewed{}, changed
	}
	inv, err := w.s.inventory(ctx, userID)
	if err != nil {
		return Reviewed{}, scheduleFault(err)
	}
	targets := make([]Frozen, 0, len(snap.Targets))
	for _, t := range snap.Targets {
		cur, ok := inv.byID(jsonMember(t, "id"))
		if !ok {
			return Reviewed{}, changed
		}
		f := Frozen{hop: cur, Route: inv.route(cur)}
		if !samePrint(f.resource(), t) || !inv.targetSupported(cur) {
			return Reviewed{}, changed
		}
		targets = append(targets, f)
	}
	digests, err := w.s.keyDigests(ctx, userID, targets)
	if err != nil {
		if Code(err) == "key_unavailable" {
			return Reviewed{}, changed
		}
		return Reviewed{}, scheduleFault(err)
	}
	if !maps.Equal(digests, snap.KeyDigests) {
		return Reviewed{}, changed
	}
	bindings, err := w.s.bindings(ctx, userID, targets, false)
	if err != nil {
		return Reviewed{}, scheduleFault(err)
	}
	return Reviewed{Runbook: books[i], Targets: targets, KeyDigests: digests, Bindings: bindings}, nil
}

// samePrint compares profile_fingerprint of two targets; it covers the
// jump host through route_fingerprint. A target without one never
// matches.
func samePrint(a, b jsontext.Value) bool {
	x, okX := vault.RecordFingerprint(a)
	y, okY := vault.RecordFingerprint(b)
	return okX && okY && x == y
}

// resource is the target as the Python release froze it: the saved
// host's resource and, behind a jump host, the jump host's in "route".
func (f Frozen) resource() jsontext.Value {
	members := slices.Clone(f.Page)
	if f.Route != nil {
		members = slices.DeleteFunc(members, func(m pyjson.Member) bool { return m.Name == "route" })
		members = append(members, pyjson.Member{Name: "route", Value: pyjson.Object(f.Route.Page)})
	}
	return pyjson.Object(members)
}

// hostKeyFault is a host_key_required review failure that names the
// saved hosts (the hostsError of the schedule routes).
type hostKeyFault struct {
	error
	hosts []string
}

func (e hostKeyFault) Hosts() []string { return e.hosts }
func (e hostKeyFault) Unwrap() error   { return e.error }

// scheduleFault turns an error of the run side into the fault the
// schedule routes answer with; the codes are the same as in Python.
func scheduleFault(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := errors.AsType[*storageError](err); ok {
		return fault.Wrap(fault.StorageError, err, "")
	}
	e, ok := errors.AsType[*Error](err)
	if !ok {
		return err
	}
	f := fault.New(fault.Code(e.Code), "")
	if len(e.Hosts) > 0 {
		return hostKeyFault{f, e.Hosts}
	}
	return f
}
