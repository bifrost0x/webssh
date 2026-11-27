package main

import (
	"context"

	"github.com/bifrost0x/webssh/internal/audit"
	"github.com/bifrost0x/webssh/internal/auth/stepup"
	"github.com/bifrost0x/webssh/internal/hostops"
	"github.com/bifrost0x/webssh/internal/settings"
	"github.com/bifrost0x/webssh/internal/terminal"
)

// serveropsArea wires the area "serverops" (HO1): server operations, insights and Herdr (internal/hostops, internal/ssh/remotecmd).
// HO1 fills in the hooks; no other package edits this file.
func serveropsArea() extension {
	return extension{
		name: "serverops",
		wire: func(sys *system) error {
			switches := serverSwitches{sys.settings}
			live := liveSessions{sys.terminal}
			ops := &hostops.Operations{Sessions: live, Switches: switches, StepUp: sys.stepup, Audit: sys.audit, Logger: sys.log}
			ops.Register(sys.edge.Mux())
			unsubscribe := sys.sessions.Subscribe(ops.Revoked)
			sys.closers = append(sys.closers, func() error { unsubscribe(); return nil })
			// The overview is the terminal's Herdr decision (wire_terminal.go),
			// read again on every snapshot request.
			diag := &hostops.Diagnostics{Sessions: live, Switches: switches, Herdr: herdrGrants{sys}, Log: sys.log,
				HerdrPerMinute: sys.cfg.Terminal.MaxConnectionsPerUser * 12}
			sys.realtime.Mount(diag.Routes()...)
			return nil
		},
	}
}

var (
	_ hostops.Sessions      = liveSessions{}
	_ hostops.Switches      = serverSwitches{}
	_ hostops.HerdrOverview = herdrGrants{}
	_ hostops.StepUp        = (*stepup.Service)(nil)
	_ hostops.Auditor       = (*audit.Logger)(nil)
)

// liveSessions adapts the terminal's connected sessions
// (terminal.Manager.SessionConn) to hostops: commands run on a separate
// channel of the session's own connection, which stays the session's.
type liveSessions struct{ m *terminal.Manager }

func (l liveSessions) Live(owner int64, id string) (hostops.Live, bool) {
	if l.m == nil {
		return hostops.Live{}, false
	}
	s, err := l.m.SessionConn(owner, id)
	if err != nil {
		return hostops.Live{}, false
	}
	return hostops.Live{Exec: s.Conn, Host: s.Host, Port: s.Port, Username: s.Username, ProfileID: s.ProfileID,
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
