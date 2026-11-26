package settings

import (
	"encoding/json/jsontext"

	"github.com/bifrost0x/webssh/internal/fault"
)

// preferenceFields are the members of POST /api/account/preferences, in
// the order the Python release checks them.
var preferenceFields = []string{
	keyStartPage, keyOverviewLayout, keyOverviewReachability, keyTerminalAppearance,
	keySyncTerminalDir, keyTheme, keyConfirmSessionClose, keyDisconnectAction, keySessionDuration,
}

// parsePreferences turns the request body into changes and refuses it
// with the message of the first invalid member, like the Python route.
func parsePreferences(body map[string]jsontext.Value) (Changes, error) {
	if len(body) == 0 {
		return Changes{}, fault.New(fault.InvalidRequest, msgNothingToChange)
	}
	for name := range body {
		if !in(preferenceFields, name) {
			return Changes{}, fault.New(fault.InvalidRequest, msgNothingToChange)
		}
	}
	var c Changes
	choice := func(v jsontext.Value, set []string, msg string) (*string, error) {
		s, ok := asString(v)
		if !ok || !in(set, s) {
			return nil, invalid(msg)
		}
		return &s, nil
	}
	flag := func(v jsontext.Value, msg string) (*bool, error) {
		b, ok := asBool(v)
		if !ok {
			return nil, invalid(msg)
		}
		return &b, nil
	}
	var err error
	for _, name := range preferenceFields {
		v, ok := body[name]
		if !ok {
			continue
		}
		switch name {
		case keyStartPage:
			c.StartPage, err = choice(v, StartPages, msgInvalidStartPage)
		case keyOverviewLayout:
			c.OverviewLayout, err = choice(v, OverviewLayouts, msgInvalidLayout)
		case keyOverviewReachability:
			c.OverviewReachability, err = choice(v, OverviewReachabilityMode, msgInvalidReach)
		case keyTerminalAppearance:
			if !ValidTerminalAppearance(v) {
				err = invalid(msgInvalidAppearance)
			}
			c.TerminalAppearance = v
		case keySyncTerminalDir:
			c.SyncTerminalDirectory, err = flag(v, msgInvalidSync)
		case keyTheme:
			c.Theme, err = choice(v, Themes, msgInvalidTheme)
		case keyConfirmSessionClose:
			c.ConfirmSessionClose, err = flag(v, msgInvalidConfirm)
		case keyDisconnectAction:
			c.DisconnectSessionAction, err = choice(v, DisconnectSessionActions, msgInvalidDisconnect)
		case keySessionDuration:
			n, ok := asInt(v)
			if !ok || !in(SessionDurations, int(n)) {
				err = invalid(msgInvalidDuration)
			}
			d := int(n)
			c.SessionDurationMinutes = &d
		}
		if err != nil {
			return Changes{}, err
		}
	}
	return c, nil
}
