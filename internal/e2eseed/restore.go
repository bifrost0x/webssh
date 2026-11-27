package e2eseed

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// maxFixtureSessions bounds the restorable sessions one request creates,
// as in tests/e2e/workspace_restore.py.
const maxFixtureSessions = 12

// FixtureSessions is provided by internal/terminal in the e2e build: fake
// connected sessions that the real attach, restore and transport paths
// treat like live ones.
type FixtureSessions interface {
	// ReplaceFixtureSessions ends the owner's earlier fixture sessions and
	// creates count new, connected and restorable ones for the owner. It
	// never touches sessions that are not fixtures or belong to someone
	// else, and returns the new session IDs.
	ReplaceFixtureSessions(ctx context.Context, peer protocol.Peer, owner int64, count int) ([]string, error)
}

// WorkspaceRestoreRequest is the payload of TypeWorkspaceRestore. A
// missing count means one session; null is not a count.
type WorkspaceRestoreRequest struct {
	Count jsontext.Value `json:"count"`
	n     int
}

// Validate applies the default and the bound.
func (r *WorkspaceRestoreRequest) Validate() error {
	r.n = 1
	if r.Count == nil {
		return nil
	}
	if r.Count.Kind() != '0' || json.Unmarshal(r.Count, &r.n) != nil || r.n < 0 || r.n > maxFixtureSessions {
		return errors.New("count must be a whole number between 0 and 12")
	}
	return nil
}

// WorkspaceRestoreResult is the result of TypeWorkspaceRestore.
type WorkspaceRestoreResult struct {
	OK         bool     `json:"ok"`
	SessionIDs []string `json:"session_ids"`
}

// WorkspaceRestoreRoute is the counterpart of the socket_workspace_restore
// hook: it replaces the caller's fixture sessions with count connected,
// restorable ones.
func WorkspaceRestoreRoute(sessions FixtureSessions) protocol.Route {
	return protocol.Handle(TypeWorkspaceRestore, protocol.Spec{Mutates: true},
		func(ctx context.Context, peer protocol.Peer, req WorkspaceRestoreRequest) (WorkspaceRestoreResult, error) {
			p, err := principal.Require(ctx)
			if err != nil {
				return WorkspaceRestoreResult{}, err
			}
			ids, err := sessions.ReplaceFixtureSessions(ctx, peer, p.UserID, req.n)
			if err != nil {
				return WorkspaceRestoreResult{}, err
			}
			if ids == nil {
				ids = []string{}
			}
			return WorkspaceRestoreResult{OK: true, SessionIDs: ids}, nil
		})
}

// Hooks are the providers of the realtime test hooks.
type Hooks struct {
	OutputFlow      OutputFlow
	FixtureSessions FixtureSessions
	HerdrSessions   HerdrSessions
	// HerdrSnapshot is the path of the recorded Herdr snapshot; Run sets
	// it next to the seed file when it is empty.
	HerdrSnapshot string
}

// Routes returns the realtime routes of the seed's hooks. A hook the seed
// enables whose provider is not wired is an error.
func (s *Seed) Routes(h Hooks) ([]protocol.Route, error) {
	var routes []protocol.Route
	for _, hook := range s.TestHooks {
		switch hook.Name {
		case HookSocketOutputLoad:
			if h.OutputFlow == nil {
				return nil, errors.New("e2e seed: hook socket_output_load has no output flow")
			}
			routes = append(routes, OutputLoadRoute(h.OutputFlow))
		case HookSocketWorkspaceRestore:
			if h.FixtureSessions == nil {
				return nil, errors.New("e2e seed: hook socket_workspace_restore has no fixture sessions")
			}
			routes = append(routes, WorkspaceRestoreRoute(h.FixtureSessions))
		case HookSocketHerdrSessions:
			if h.HerdrSessions == nil {
				return nil, errors.New("e2e seed: hook socket_herdr_sessions has no fixture sessions")
			}
			snapshot, err := LoadHerdrSnapshot(h.HerdrSnapshot)
			if err != nil {
				return nil, err
			}
			routes = append(routes, HerdrRoutes(h.HerdrSessions, snapshot)...)
		}
	}
	return routes, nil
}
