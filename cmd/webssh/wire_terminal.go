package main

import (
	"context"

	"github.com/bifrost0x/webssh/internal/terminal"
)

// terminalArea wires the area "terminal" (TM1): the rest of the terminal (internal/terminal).
// TM1 fills in the hooks; no other package edits this file.
func terminalArea() extension {
	return extension{
		name: "terminal",
		prepare: func(sys *system) error {
			sys.optional.terminalHerdr = herdrGrants{sys}
			return nil
		},
	}
}

var _ terminal.HerdrGrants = herdrGrants{}

// herdrGrants decides Herdr from the administrator switch herdr_enabled
// and the options of the owner's saved host, both read at the moment of
// the decision (herdr.overview_allowed, herdr.session_mode_allowed). Any
// failure to read them is no grant.
type herdrGrants struct{ sys *system }

func (g herdrGrants) host(ctx context.Context, owner int64, profileID string) (herdr, session bool) {
	if profileID == "" || g.sys.settings == nil || g.sys.hosts == nil {
		return false, false
	}
	app, err := g.sys.settings.App(ctx)
	if err != nil || !app.HerdrEnabled {
		return false, false
	}
	t, err := g.sys.hosts.Resolve(ctx, owner, profileID)
	if err != nil {
		return false, false
	}
	return t.Display.Herdr, t.Display.Herdr && t.Display.UseHerdr
}

// Overview implements terminal.HerdrGrants.
func (g herdrGrants) Overview(ctx context.Context, owner int64, profileID string) bool {
	overview, _ := g.host(ctx, owner, profileID)
	return overview
}

// SessionMode implements terminal.HerdrGrants.
func (g herdrGrants) SessionMode(ctx context.Context, owner int64, profileID string) bool {
	_, session := g.host(ctx, owner, profileID)
	return session
}
