package terminal

import (
	"context"
	"time"

	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// HerdrGrants decides the Herdr integration for a saved host (provided by
// the owner of the Herdr overview, HO1). Overview reports whether the
// integration is on and owner's saved host profileID opts in
// (herdr.overview_allowed); SessionMode whether that host also runs Herdr
// as its session (herdr.session_mode_allowed). A failure to decide is
// false. Nothing the browser sends grants either.
type HerdrGrants interface {
	Overview(ctx context.Context, owner int64, profileID string) bool
	SessionMode(ctx context.Context, owner int64, profileID string) bool
}

// The fixed Herdr commands of the Python release (app/herdr.py). The
// lookup appends the installer's directories to the account's PATH, so
// the overview and the session mode always resolve the same binary; the
// single-quoted script reaches sh unchanged whatever the login shell is.
const (
	herdrPathPrefix       = `PATH="$PATH:$HOME/.local/bin:/usr/local/bin:/opt/homebrew/bin"`
	herdrAvailableCommand = `sh -c '` + herdrPathPrefix + `; command -v herdr >/dev/null 2>&1'`
	herdrSessionCommand   = `sh -c '` + herdrPathPrefix + `; exec herdr'`
	herdrProbeTimeout     = 3 * time.Second
)

// herdrPlan is the Herdr part of terminal.open after the checks.
type herdrPlan struct {
	overview bool // the session may be asked for its Herdr overview
	session  bool // Herdr was asked for and granted as the program
}

// planHerdr applies the order of the Python release: tmux and Herdr
// exclude each other, and the session mode excludes startup commands;
// both checks look at the request before any grant. Only the bound,
// owned saved host grants anything.
func (m *Manager) planHerdr(ctx context.Context, owner int64, req protocol.OpenTarget, t client.Target, startup string) (herdrPlan, error) {
	if req.UseHerdr && req.UseTmux {
		return herdrPlan{}, invalid("tmux and Herdr cannot be combined")
	}
	if req.UseHerdr && startup != "" {
		return herdrPlan{}, invalid("Herdr session mode cannot be combined with startup commands")
	}
	id := t.Display.ProfileID
	if m.herdr == nil || id == "" {
		return herdrPlan{}, nil
	}
	p := herdrPlan{overview: m.herdr.Overview(ctx, owner, id)}
	p.session = req.UseHerdr && p.overview && m.herdr.SessionMode(ctx, owner, id)
	return p, nil
}

// herdrAvailable re-checks the grant, since prompts may have taken long,
// and asks the host for the binary; any failure is false.
func (m *Manager) herdrAvailable(ctx context.Context, h remoteHost, owner int64, profileID string) bool {
	if m.herdr == nil || !m.herdr.SessionMode(ctx, owner, profileID) {
		return false
	}
	status, _, err := h.run(ctx, herdrAvailableCommand, herdrProbeTimeout)
	return err == nil && status == 0
}
