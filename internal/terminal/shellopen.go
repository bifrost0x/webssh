package terminal

import (
	"context"

	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// opened is the program of a new session and what it runs on.
type opened struct {
	shell client.Shell
	host  remoteHost // nil when the shell came from Shells
	tmux  *tmuxBinding
	herdr bool // Herdr runs as the program
}

// openShell opens the session's program on a connection of its own: tmux
// when planned and installed on the host, Herdr when granted and
// installed, else the login shell. Without Connections the login shell
// comes from Shells and the session has no connection for other channels.
func (m *Manager) openShell(ctx context.Context, t client.Target, ix client.Interaction, rows, cols int,
	plan tmuxPlan, hp herdrPlan) (opened, error) {
	if m.dialHost == nil {
		sh, err := m.shells.OpenShell(ctx, t, ix, rows, cols)
		return opened{shell: sh}, err
	}
	var attach string
	if plan.use {
		var err error
		if attach, err = tmuxAttachCommand(plan.program, plan.name, plan.reattach); err != nil {
			return opened{}, err
		}
	}
	h, err := m.dialHost(ctx, t, ix)
	if err != nil {
		return opened{}, err
	}
	o, err := m.startProgram(ctx, h, t, rows, cols, plan, hp, attach)
	if err != nil {
		_ = h.Close()
		return opened{}, err
	}
	o.shell, o.host = ownedShell{o.shell, h}, h
	return o, nil
}

func (m *Manager) startProgram(ctx context.Context, h remoteHost, t client.Target, rows, cols int,
	plan tmuxPlan, hp herdrPlan, attach string) (opened, error) {
	switch {
	case plan.use:
		// Probe on a separate channel: no error text to match, and tmux's
		// first screen is not swallowed.
		status, _, err := h.run(ctx, tmuxProbeCommand, tmuxProbeTimeout)
		if ctx.Err() != nil {
			return opened{}, ctx.Err()
		}
		if err == nil && status == 0 {
			sh, err := h.commandShell(ctx, attach, rows, cols)
			if err != nil {
				return opened{}, err
			}
			return opened{shell: sh, tmux: &tmuxBinding{name: plan.name, reattach: plan.reattach, host: h}}, nil
		}
		m.log.Warn("tmux not found on target host, falling back to regular shell", "host", t.Hop.Host, "port", t.Hop.Port)
	case hp.session:
		// Not persistent and unnamed: Herdr keeps its own default session,
		// and nothing is stopped on the host when this channel closes.
		ok := m.herdrAvailable(ctx, h, t.Owner, t.Display.ProfileID)
		if ctx.Err() != nil {
			return opened{}, ctx.Err()
		}
		if ok {
			sh, err := h.commandShell(ctx, herdrSessionCommand, rows, cols)
			if err != nil {
				return opened{}, err
			}
			return opened{shell: sh, herdr: true}, nil
		}
		m.log.Warn("Herdr not found on target host, falling back to regular shell", "host", t.Hop.Host, "port", t.Hop.Port)
	}
	sh, err := h.shell(ctx, rows, cols)
	return opened{shell: sh}, err
}
