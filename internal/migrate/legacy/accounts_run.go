package legacy

import (
	"context"
	"fmt"
	"slices"
)

// accountStep marks a step whose legacy data lies in the stores of each
// account and whose Read, Write and Verify handle every account on its
// own: the accounts Source.AccountRows returns, the files below their
// user directories and the rows written for them, never another
// account's. The run gives each account fresh instances of such steps and
// drops them before the next account, so the memory a migration needs is
// bounded by the stores of one account and not by those of all accounts
// together (a per-user store may hold up to 64 MiB).
//
// An account step reads, writes and verifies one account before the next
// account is read; its Verify therefore runs right after its Write, before
// later steps write. Account steps only read what earlier steps wrote for
// the same account.
type accountStep interface {
	accountScoped() bool
}

func isAccountStep(s Step) bool {
	a, ok := s.(accountStep)
	return ok && a.accountScoped()
}

// segment is a step over the whole source, or a run of consecutive account
// steps in dependency order.
type segment struct {
	step     Step
	accounts []registered
	// reports are the combined reports of the account steps, filled by
	// the write.
	reports []StepReport
}

// eachAccount calls fn with fresh instances of the segment's account
// steps, account by account and within an account in dependency order,
// with the source limited to that account. Without accounts it calls fn
// once per step with an empty scope, so that every step still reports.
func (r *run) eachAccount(seg *segment, fn func(i int, s Step) error) error {
	scopes := make([][]AccountRow, 0, max(len(r.accounts), 1))
	for _, a := range r.accounts {
		scopes = append(scopes, []AccountRow{a})
	}
	if len(scopes) == 0 {
		scopes = append(scopes, nil)
	}
	defer r.src.scopeTo(nil, false)
	for _, scope := range scopes {
		r.src.scopeTo(scope, true)
		for i, reg := range seg.accounts {
			s, err := reg.instance()
			if err != nil {
				return stop("", CodeStepFailed, "the migration steps are inconsistent", err)
			}
			if err := fn(i, s); err != nil {
				return err
			}
		}
	}
	return nil
}

// readAccounts is the reading of the account steps before anything is
// written: every account's stores are read and checked, then dropped.
func (r *run) readAccounts(ctx context.Context, seg *segment) error {
	return r.eachAccount(seg, func(_ int, s Step) error {
		if err := s.Read(ctx, r.src); err != nil {
			return stepStop(s.Entity(), "the legacy data could not be read", err)
		}
		return nil
	})
}

// writeAccounts reads, writes and verifies the account steps account by
// account and keeps only their reports.
func (r *run) writeAccounts(ctx context.Context, seg *segment, write func(Step) error, verify func(Step) error) error {
	seg.reports = make([]StepReport, len(seg.accounts))
	err := r.eachAccount(seg, func(i int, s Step) error {
		if err := s.Read(ctx, r.src); err != nil {
			return stepStop(s.Entity(), "the legacy data could not be read", err)
		}
		if err := write(s); err != nil {
			return err
		}
		if err := verify(s); err != nil {
			return err
		}
		seg.reports[i] = combineReports(seg.reports[i], s.Report())
		return nil
	})
	for i := range seg.reports {
		seg.reports[i] = finishReport(seg.reports[i])
	}
	return err
}

// combineReports adds the report of one account to the reports of the
// accounts before it.
func combineReports(acc, next StepReport) StepReport {
	if acc.Entity == "" {
		return next
	}
	acc.Read += next.Read
	acc.Written += next.Written
	acc.Discarded += next.Discarded
	acc.accounts += next.accounts
	if acc.accountNote == "" {
		acc.accountNote = next.accountNote
	}
	acc.Notes = append(acc.Notes, next.Notes...)
	acc.Flagged = append(acc.Flagged, next.Flagged...)
	acc.KeptInPlace = append(acc.KeptInPlace, next.KeptInPlace...)
	acc.Settings = append(acc.Settings, next.Settings...)
	acc.Warnings = append(acc.Warnings, next.Warnings...)
	acc.UserActions = append(acc.UserActions, next.UserActions...)
	return acc
}

// finishReport drops the notes every account repeats.
func finishReport(r StepReport) StepReport {
	seen := map[string]bool{}
	var notes []string
	for _, n := range r.Notes {
		if !seen[n] {
			seen[n] = true
			notes = append(notes, n)
		}
	}
	r.Notes = notes
	return r
}

// withAccountNote writes the note that counts accounts into Notes.
func withAccountNote(r StepReport) StepReport {
	if r.accountNote != "" {
		r.Notes = append(slices.Clip(r.Notes), fmt.Sprintf(r.accountNote, r.accounts))
	}
	r.accountNote, r.accounts = "", 0
	return r
}
