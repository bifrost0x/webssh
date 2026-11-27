package legacy

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/bifrost0x/webssh/internal/automation"
	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/store"
)

// AddAutomation registers the steps of the automation runbooks (E29) and
// the run history (E31).
func AddAutomation(r *Registry) error {
	r.Schemas(automation.Schema())
	return errors.Join(
		r.Add(GroupAutomation, func() Step { return &runbooksStep{} }),
		r.Add(GroupAutomation, func() Step { return &runsStep{} }),
	)
}

// runbooksStep migrates entity E29: automation.json of every account,
// each runbook verbatim and in order. A store the Python release cannot
// read (_valid_books) stops the migration; runbooks above the current
// count limit are migrated and reported.
type runbooksStep struct{ users []userRunbooks }

type userRunbooks struct {
	id    int64
	books []automation.Runbook
}

func (*runbooksStep) Entity() string { return "E29" }

func (*runbooksStep) Version() int { return 1 }

func (s *runbooksStep) Read(ctx context.Context, src *Source) error {
	rows, err := src.AccountRows(ctx)
	if err != nil {
		return err
	}
	for _, a := range rows {
		raw, found, err := automationFile(src, a.ID, "automation.json", "automation")
		if err != nil || !found {
			if err != nil {
				return err
			}
			continue
		}
		books, err := parseRunbooks(raw)
		if err != nil {
			return &StepError{UserID: a.ID, Record: "automation.json", Err: err}
		}
		s.users = append(s.users, userRunbooks{id: a.ID, books: books})
	}
	return nil
}

// automationFile reads a store of the automation as bytes.
func automationFile(src *Source, userID int64, file, store string) ([]byte, bool, error) {
	raw, err := src.readStoreBytes(userDir(userID)+"/"+file, store)
	if errors.Is(err, ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, &StepError{UserID: userID, Record: file, Err: err}
	}
	return raw, true, nil
}

// parseRunbooks is _valid_books without the count limit: version 1, a
// list of runbooks that each equal their normalized form, unique ids.
func parseRunbooks(raw []byte) ([]automation.Runbook, error) {
	doc, rep, err := pyjson.Load(raw)
	if err != nil || rep.LoneSurrogates {
		return nil, errors.New("legacy: automation.json is not readable")
	}
	_, ok := pyjson.Members(doc)
	version, _ := pyjson.Get(doc, "version")
	list, okList := pyjson.Get(doc, "runbooks")
	items, isList := pyjson.Items(list)
	if !ok || string(version) != "1" || !okList || !isList {
		return nil, errors.New("legacy: automation.json has an unknown shape")
	}
	seen := map[string]bool{}
	books := make([]automation.Runbook, 0, len(items))
	for i, item := range items {
		b, err := automation.NormalizeRunbook(item)
		if err != nil || !automation.SameValue(b.Value(), item) || seen[b.ID] {
			return nil, fmt.Errorf("legacy: runbook %d of automation.json is invalid", i)
		}
		seen[b.ID] = true
		books = append(books, b)
	}
	return books, nil
}

func (s *runbooksStep) Write(ctx context.Context, tx *store.Tx, _ Sealer) error {
	for _, u := range s.users {
		if err := automation.WriteRunbooksTx(ctx, tx, u.id, u.books); err != nil {
			return &StepError{UserID: u.id, Record: "automation.json", Err: err}
		}
	}
	return nil
}

// Verify reads every library back and compares each runbook and its
// digest, which binds the grants of the schedules.
func (s *runbooksStep) Verify(ctx context.Context, tx *store.Tx, _ Opener) error {
	for _, u := range s.users {
		got, err := automation.ReadRunbooksTx(ctx, tx, u.id)
		if err != nil {
			return &StepError{UserID: u.id, Err: err}
		}
		if len(got) != len(u.books) {
			return &StepError{UserID: u.id, Err: errors.New("legacy: the stored runbooks differ from automation.json")}
		}
		for i := range got {
			if got[i].Digest() != u.books[i].Digest() || !bytes.Equal(got[i].Value(), u.books[i].Value()) {
				return &StepError{UserID: u.id, Record: u.books[i].ID, Err: errors.New("legacy: a stored runbook differs from automation.json")}
			}
		}
	}
	return nil
}

func (s *runbooksStep) Report() StepReport {
	r := StepReport{Entity: "E29", Version: 1}
	for _, u := range s.users {
		r.Read += len(u.books)
		r.Written += len(u.books)
		for i := automation.MaxRunbooks; i < len(u.books); i++ {
			r.Flagged = append(r.Flagged, Flag{UserID: u.id, ID: u.books[i].ID, Reason: "runbook_above_limit"})
		}
	}
	return r
}

// runsStep migrates entity E31: automation-runs.json of every account,
// each run verbatim with its member order, so the export is the same
// text. Runs that were still queued or running get the load-time rule of
// the Python release (unknown, run_interrupted), and the history is
// trimmed as Python trims it when it records that.
type runsStep struct{ users []userRuns }

type userRuns struct {
	id          int64
	runs        []automation.Run
	interrupted int
	trimmed     int
}

func (*runsStep) Entity() string { return "E31" }

func (*runsStep) Version() int { return 1 }

func (s *runsStep) Read(ctx context.Context, src *Source) error {
	rows, err := src.AccountRows(ctx)
	if err != nil {
		return err
	}
	for _, a := range rows {
		raw, found, err := automationFile(src, a.ID, "automation-runs.json", "automation_runs")
		if err != nil || !found {
			if err != nil {
				return err
			}
			continue
		}
		doc, rep, err := pyjson.Load(raw)
		if err != nil || rep.LoneSurrogates {
			return &StepError{UserID: a.ID, Record: "automation-runs.json", Err: errors.New("legacy: automation-runs.json is not readable")}
		}
		runs, err := automation.ParseHistory(doc)
		if err != nil {
			return &StepError{UserID: a.ID, Record: "automation-runs.json", Err: err}
		}
		u := userRuns{id: a.ID}
		for i := range runs {
			if automation.Recover(&runs[i]) {
				u.interrupted++
			}
		}
		u.runs = runs
		if u.interrupted > 0 {
			u.runs = automation.Trim(runs)
			u.trimmed = len(runs) - len(u.runs)
		}
		s.users = append(s.users, u)
	}
	return nil
}

func (s *runsStep) Write(ctx context.Context, tx *store.Tx, _ Sealer) error {
	for _, u := range s.users {
		if err := automation.ImportRunsTx(ctx, tx, u.id, u.runs); err != nil {
			return &StepError{UserID: u.id, Record: "automation-runs.json", Err: err}
		}
	}
	return nil
}

// Verify reads every history back and compares the JSON and CSV exports
// of each run with those of the record that was read.
func (s *runsStep) Verify(ctx context.Context, tx *store.Tx, _ Opener) error {
	for _, u := range s.users {
		got, err := automation.ExportRunsTx(ctx, tx, u.id)
		if err != nil {
			return &StepError{UserID: u.id, Err: err}
		}
		if len(got) != len(u.runs) {
			return &StepError{UserID: u.id, Err: errors.New("legacy: the stored runs differ from automation-runs.json")}
		}
		for i := range got {
			if !bytes.Equal(automation.ExportJSON(got[i]), automation.ExportJSON(u.runs[i])) ||
				!bytes.Equal(automation.ExportCSV(got[i]), automation.ExportCSV(u.runs[i])) {
				return &StepError{UserID: u.id, Record: u.runs[i].ID, Err: errors.New("legacy: a stored run differs from automation-runs.json")}
			}
		}
	}
	return nil
}

func (s *runsStep) Report() StepReport {
	r := StepReport{Entity: "E31", Version: 1}
	for _, u := range s.users {
		r.Read += len(u.runs) + u.trimmed
		r.Written += len(u.runs)
		if u.interrupted > 0 {
			r.Notes = append(r.Notes, fmt.Sprintf("user %d: %d unfinished runs recorded as unknown (run_interrupted)", u.id, u.interrupted))
		}
		if u.trimmed > 0 {
			r.Notes = append(r.Notes, fmt.Sprintf("user %d: %d oldest runs dropped to keep the history within its size limit, as the Python release does", u.id, u.trimmed))
		}
	}
	return r
}
