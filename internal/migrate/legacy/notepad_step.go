package legacy

import (
	"context"
	"errors"

	"github.com/bifrost0x/webssh/internal/hostops"
	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/store"
)

// notepadStep migrates entity A05: the notepad of settings.json becomes
// the note without a host in hostops_notes (D-11, specification 4.5). An
// empty notepad creates no row. E25 has checked the document.
type notepadStep struct {
	notes []note
}

type note struct {
	userID    int64
	profileID string
	body      string
	revision  int64
}

// notepadRevision is the revision of a migrated notepad; SaveNote starts
// a new notepad at the same value.
const notepadRevision = 1

func (*notepadStep) Entity() string { return "A05" }

func (*notepadStep) Version() int { return 1 }

func (s *notepadStep) Read(ctx context.Context, src *Source) error {
	rows, err := src.AccountRows(ctx)
	if err != nil {
		return err
	}
	for _, a := range rows {
		doc, found, err := userStore(src, a.ID, "settings")
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		v, ok := pyjson.Get(doc.Raw, "notepad")
		if !ok {
			continue
		}
		body, ok := pyString(v)
		if !ok {
			return &StepError{UserID: a.ID, Record: "settings.json", Err: errors.New("legacy: notepad is not text")}
		}
		if body != "" {
			s.notes = append(s.notes, note{userID: a.ID, body: body, revision: notepadRevision})
		}
	}
	return nil
}

func (s *notepadStep) Write(ctx context.Context, tx *store.Tx, _ Sealer) error {
	return importNotes(ctx, tx, s.notes)
}

func (s *notepadStep) Verify(ctx context.Context, tx *store.Tx, _ Opener) error {
	return verifyNotes(ctx, tx, s.notes)
}

func importNotes(ctx context.Context, tx *store.Tx, notes []note) error {
	for _, n := range notes {
		if err := hostops.ImportNote(ctx, tx, n.userID, n.profileID, n.body, n.revision); err != nil {
			return &StepError{UserID: n.userID, Record: n.profileID, Err: err}
		}
	}
	return nil
}

func verifyNotes(ctx context.Context, tx *store.Tx, notes []note) error {
	for _, n := range notes {
		body, rev, found, err := hostops.NoteTx(ctx, tx, n.userID, n.profileID)
		if err != nil || !found || body != n.body || rev != n.revision {
			return &StepError{UserID: n.userID, Record: n.profileID, Err: errors.Join(errors.New("legacy: the stored note differs"), err)}
		}
	}
	return nil
}

func (s *notepadStep) Report() StepReport {
	return StepReport{Entity: "A05", Version: 1, Read: len(s.notes), Written: len(s.notes)}
}
