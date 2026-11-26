package legacy

import (
	"context"
	"errors"
	"fmt"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/store"
)

// historyScopeStep verifies entity A04: the browser-storage namespace Go
// derives for each migrated account equals the one the Python release
// derives (app/browser_identity.py), bit for bit, so the browser keeps
// the recent connections, favourites and topology layout (D-10). The
// input, accounts_users.history_generation, is written by E01.
type historyScopeStep struct {
	scopes map[int64]string
	order  []int64
}

// browserScoper derives the namespace; *keyring.Ring provides it.
type browserScoper interface {
	BrowserScope(userID int64, username, generation string) string
}

func (*historyScopeStep) Entity() string { return "A04" }

func (*historyScopeStep) Version() int { return 1 }

func (s *historyScopeStep) Read(ctx context.Context, src *Source) error {
	users, err := src.Users(ctx)
	if err != nil {
		return err
	}
	s.scopes = map[int64]string{}
	for _, u := range users {
		scope, err := src.ConnectionHistoryScope(u)
		if err != nil {
			return &StepError{UserID: u.ID, Err: err}
		}
		s.scopes[u.ID] = scope
		s.order = append(s.order, u.ID)
	}
	return nil
}

func (*historyScopeStep) Write(context.Context, *store.Tx, Sealer) error { return nil }

func (s *historyScopeStep) Verify(ctx context.Context, tx *store.Tx, open Opener) error {
	scoper, ok := open.(browserScoper)
	if !ok {
		return fmt.Errorf("legacy: %T cannot derive the browser namespace", open)
	}
	for _, id := range s.order {
		a, err := accounts.GetTx(ctx, tx, id)
		if err != nil {
			return &StepError{UserID: id, Err: err}
		}
		if scoper.BrowserScope(a.ID, a.Username, a.HistoryGeneration) != s.scopes[id] {
			return &StepError{UserID: id, Err: errors.New("legacy: the browser history namespace differs from the Python release's")}
		}
	}
	return nil
}

func (s *historyScopeStep) Report() StepReport {
	return StepReport{Entity: "A04", Version: 1, Read: len(s.order), Written: len(s.order),
		Notes: []string{"browser history namespaces verified equal for every account"}}
}
