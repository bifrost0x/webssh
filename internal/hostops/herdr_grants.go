package hostops

import "context"

// HerdrGrants decides the Herdr overview and session mode of a saved host
// for the terminal (terminal.Herdr through cmd/webssh): the integration
// is on and the owner's saved host has the option; the session mode needs
// use_herdr as well (overview_allowed, session_mode_allowed). Any failure
// is a refusal.
type HerdrGrants struct {
	Switches Switches
	Profiles Profiles
}

// Grants reports the overview and the session mode.
func (g HerdrGrants) Grants(ctx context.Context, owner int64, profileID string) (overview, session bool) {
	if profileID == "" || g.Switches == nil || g.Profiles == nil || !g.Switches.HerdrEnabled(ctx) {
		return false, false
	}
	herdr, useHerdr, err := g.Profiles.HerdrOptions(ctx, owner, profileID)
	if err != nil {
		return false, false
	}
	return herdr, herdr && useHerdr
}

// Commands are the fixed lookup and client command lines.
func (HerdrGrants) Commands() (probe, run string) { return HerdrProbeCommand, HerdrSessionCommand }
