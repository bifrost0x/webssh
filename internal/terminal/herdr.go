package terminal

import (
	"context"
	"time"

	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// Herdr grants the Herdr overview and the Herdr session mode of a saved
// host (internal/hostops through cmd/webssh). Only the owner's saved host
// grants either; nothing the browser sends can.
type Herdr interface {
	// Grants reports the overview and the session mode for profileID of
	// owner: the integration is on and the saved host opts in. A failure
	// to decide is a refusal.
	Grants(ctx context.Context, owner int64, profileID string) (overview, session bool)
	// Commands are the fixed command lines that look for the Herdr client
	// and run it.
	Commands() (probe, run string)
}

// herdrProbeTimeout bounds the lookup of the Herdr client
// (HERDR_PROBE_TIMEOUT of the Python release).
const herdrProbeTimeout = 3 * time.Second

// herdrPlan is the Herdr part of terminal.open after the checks.
type herdrPlan struct {
	overview bool // the saved host grants the overview now
	session  bool // run the Herdr client instead of the login shell
}

// planHerdr checks the Herdr fields of terminal.open before anything is
// dialled, with the rules of the Python release.
func (m *Manager) planHerdr(ctx context.Context, owner int64, req protocol.OpenTarget, t client.Target) (herdrPlan, error) {
	if req.UseHerdr && req.UseTmux {
		return herdrPlan{}, invalid("tmux and Herdr cannot be combined")
	}
	if req.UseHerdr && t.Display.StartupCommand {
		return herdrPlan{}, invalid("Herdr session mode cannot be combined with startup commands")
	}
	if m.herdr == nil || t.Display.ProfileID == "" {
		return herdrPlan{}, nil
	}
	overview, session := m.herdr.Grants(ctx, owner, t.Display.ProfileID)
	return herdrPlan{overview: overview, session: req.UseHerdr && overview && session && m.dialHost != nil}, nil
}

// openHerdr opens the Herdr client with a PTY when the grant still holds
// (prompts may have taken long) and the fixed lookup finds it; otherwise
// the login shell. ok reports that Herdr runs. Nothing is stopped on the
// host when the channel closes: Herdr keeps its own default session.
func (m *Manager) openHerdr(ctx context.Context, owner int64, t client.Target, ix client.Interaction, rows, cols int) (client.Shell, bool, error) {
	h, err := m.dialHost(ctx, t, ix)
	if err != nil {
		return nil, false, err
	}
	probe, run := m.herdr.Commands()
	_, session := m.herdr.Grants(ctx, owner, t.Display.ProfileID)
	available := false
	if session {
		status, _, perr := h.run(ctx, probe, herdrProbeTimeout)
		available = perr == nil && status == 0
	}
	if ctx.Err() != nil {
		_ = h.Close()
		return nil, false, ctx.Err()
	}
	var sh client.Shell
	if available {
		sh, err = h.commandShell(ctx, run, rows, cols)
	} else {
		m.log.Warn("Herdr not found on target host, falling back to regular shell", "host", t.Hop.Host, "port", t.Hop.Port)
		sh, err = h.shell(ctx, rows, cols)
	}
	if err != nil {
		_ = h.Close()
		return nil, false, err
	}
	return ownedShell{sh, h}, available, nil
}

// withHerdr records the Herdr grants in the session description. The
// overview is granted only if it still holds after the connection.
func (m *Manager) withHerdr(ctx context.Context, owner int64, info protocol.SessionInfo, plan herdrPlan, running bool) protocol.SessionInfo {
	if plan.overview && m.herdr != nil {
		info.Herdr, _ = m.herdr.Grants(ctx, owner, info.ProfileID)
	}
	info.UseHerdr = running
	return info
}
