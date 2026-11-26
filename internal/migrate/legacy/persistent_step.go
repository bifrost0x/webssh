package legacy

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/bifrost0x/webssh/internal/store"
)

// PersistentSessionStore takes over the persistent tmux sessions (entity
// A01). internal/terminal provides it through an adapter of the
// composition root; the migration declares it, as the consumer.
type PersistentSessionStore interface {
	Schema() store.Schema
	// ImportPersistentTx stores one session as not connected, with its
	// tmux name byte for byte.
	ImportPersistentTx(ctx context.Context, tx *store.Tx, p PersistentSession) error
	// PersistentTx returns the stored sessions ordered by RowID, for the
	// verification.
	PersistentTx(ctx context.Context, tx *store.Tx) ([]PersistentSession, error)
}

// persistentSessionsStep migrates entity A01 (D-09): every ssh_sessions
// row of a persistent tmux session with its tmux name copied byte for
// byte (it holds a random part and cannot be derived again, I-11) and its
// display name. Other rows are E14.
type persistentSessionsStep struct {
	store    PersistentSessionStore
	sessions []PersistentSession
	ids      map[int64]bool
}

func (*persistentSessionsStep) Entity() string { return "A01" }

func (*persistentSessionsStep) Version() int { return 1 }

func (s *persistentSessionsStep) Read(ctx context.Context, src *Source) error {
	var err error
	if s.sessions, _, err = src.PersistentSessions(ctx); err != nil {
		return err
	}
	_, s.ids, err = accountIDs(ctx, src)
	return err
}

func (s *persistentSessionsStep) Write(ctx context.Context, tx *store.Tx, _ Sealer) error {
	for _, p := range s.sessions {
		if !s.ids[p.UserID] {
			continue // a row of a deleted account; kept in the legacy database
		}
		if err := s.store.ImportPersistentTx(ctx, tx, p); err != nil {
			return &StepError{UserID: p.UserID, Record: p.SessionID, Err: err}
		}
	}
	return nil
}

func (s *persistentSessionsStep) Verify(ctx context.Context, tx *store.Tx, _ Opener) error {
	got, err := s.store.PersistentTx(ctx, tx)
	if err != nil {
		return err
	}
	want := slices.DeleteFunc(slices.Clone(s.sessions), func(p PersistentSession) bool { return !s.ids[p.UserID] })
	if !slices.Equal(got, want) {
		return errors.New("legacy: the stored persistent sessions differ")
	}
	return nil
}

func (s *persistentSessionsStep) Report() StepReport {
	r := StepReport{Entity: "A01", Version: 1, Read: len(s.sessions)}
	for _, p := range s.sessions {
		if s.ids[p.UserID] {
			r.Written++
		} else {
			r.Notes = append(r.Notes, fmt.Sprintf("session row %d belongs to a deleted account and stays in app.db", p.RowID))
		}
	}
	return r
}

// countPersistentSessions counts the sessions left in place when the
// build has no terminal store.
func countPersistentSessions(ctx context.Context, src *Source) (int, error) {
	sessions, _, err := src.PersistentSessions(ctx)
	return len(sessions), err
}
