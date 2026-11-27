package main

import (
	"context"

	"github.com/bifrost0x/webssh/internal/audit"
	"github.com/bifrost0x/webssh/internal/auth/stepup"
	"github.com/bifrost0x/webssh/internal/hostops"
	"github.com/bifrost0x/webssh/internal/hosts"
	"github.com/bifrost0x/webssh/internal/settings"
	"github.com/bifrost0x/webssh/internal/terminal"
)

// serveropsArea wires the area "serverops" (HO1): server operations, insights and Herdr (internal/hostops, internal/ssh/remotecmd).
// HO1 fills in the hooks; no other package edits this file.
func serveropsArea() extension {
	return extension{
		name: "serverops",
		prepare: func(sys *system) error {
			// The saved hosts are built after prepare; they are looked up
			// when a session asks.
			sys.optional.terminalHerdr = hostops.HerdrGrants{Switches: serverSwitches{sys.settings}, Profiles: laterProfiles{sys}}
			return nil
		},
		wire: func(sys *system) error {
			switches := serverSwitches{sys.settings}
			live := liveSessions{sys.terminal}
			ops := &hostops.Operations{Sessions: live, Switches: switches, StepUp: sys.stepup, Audit: sys.audit, Logger: sys.log}
			ops.Register(sys.edge.Mux())
			unsubscribe := sys.sessions.Subscribe(ops.Revoked)
			sys.closers = append(sys.closers, func() error { unsubscribe(); return nil })
			diag := &hostops.Diagnostics{Sessions: live, Switches: switches, Profiles: sys.hosts, Log: sys.log,
				HerdrPerMinute: sys.cfg.Terminal.MaxConnectionsPerUser * 12}
			sys.realtime.Mount(diag.Routes()...)
			return nil
		},
	}
}

var (
	_ hostops.Sessions = liveSessions{}
	_ hostops.Switches = serverSwitches{}
	_ hostops.Profiles = (*hosts.Service)(nil)
	_ hostops.StepUp   = (*stepup.Service)(nil)
	_ hostops.Auditor  = (*audit.Logger)(nil)
	_ terminal.Herdr   = hostops.HerdrGrants{}
)

// laterProfiles reads the saved hosts of the system once they exist.
type laterProfiles struct{ sys *system }

func (l laterProfiles) HerdrOptions(ctx context.Context, owner int64, profileID string) (bool, bool, error) {
	if l.sys.hosts == nil {
		return false, false, nil
	}
	return l.sys.hosts.HerdrOptions(ctx, owner, profileID)
}

// liveSessions adapts the terminal's connected sessions to hostops.
type liveSessions struct{ m *terminal.Manager }

func (l liveSessions) Live(owner int64, id string) (hostops.Live, bool) {
	if l.m == nil {
		return hostops.Live{}, false
	}
	s, ok := l.m.Live(owner, id)
	if !ok {
		return hostops.Live{}, false
	}
	return hostops.Live{Exec: s.Exec, Host: s.Host, Port: s.Port, Username: s.Username, ProfileID: s.ProfileID,
		Herdr: s.Herdr, UseHerdr: s.UseHerdr, Done: s.Done}, true
}

// serverSwitches reads the integration switches; a failure to read them
// counts as off (fail closed).
type serverSwitches struct{ s *settings.Service }

func (w serverSwitches) app(ctx context.Context) (settings.App, bool) {
	if w.s == nil {
		return settings.App{}, false
	}
	app, err := w.s.App(ctx)
	return app, err == nil
}

func (w serverSwitches) ServerOperationsEnabled(ctx context.Context) bool {
	app, ok := w.app(ctx)
	return ok && app.RuntimeFeature("server_operations_enabled").Enabled
}

func (w serverSwitches) HerdrEnabled(ctx context.Context) bool {
	app, ok := w.app(ctx)
	return ok && app.HerdrEnabled
}
