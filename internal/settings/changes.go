package settings

import (
	"encoding/json/jsontext"
	"slices"

	"github.com/bifrost0x/webssh/internal/fault"
)

// Changes are the account settings one request changes; nil fields stay
// as they are. Raw JSON fields must be compact.
type Changes struct {
	Theme                   *string
	StartPage               *string
	OverviewLayout          *string
	OverviewReachability    *string
	DisconnectSessionAction *string
	ConfirmSessionClose     *bool
	SyncTerminalDirectory   *bool
	SessionDurationMinutes  *int
	// TerminalAppearance replaces the override object.
	TerminalAppearance jsontext.Value
	// OverviewPanels replaces the arrangement; "null" restores the default.
	OverviewPanels jsontext.Value
	// OverviewDismissed replaces the acknowledged attention items.
	OverviewDismissed jsontext.Value
	// Tour records the state of the introduction tour; "completed" also
	// records the acknowledgement of the current tour.
	Tour *string
}

// Messages of the Python release for refused values; the pages show
// them.
const (
	msgInvalidTheme       = "Invalid theme"
	msgInvalidStartPage   = "Invalid start page"
	msgInvalidLayout      = "Invalid overview layout"
	msgInvalidReach       = "Invalid reachability setting"
	msgInvalidAppearance  = "Invalid terminal appearance"
	msgInvalidSync        = "Invalid directory sync setting"
	msgInvalidConfirm     = "Invalid close confirmation setting"
	msgInvalidDisconnect  = "Invalid disconnect session action"
	msgInvalidDuration    = "Invalid authentication session duration"
	msgInvalidPanels      = "Invalid layout."
	msgInvalidDismissed   = "Invalid acknowledgement list."
	msgInvalidTourState   = "Invalid tour state"
	msgNothingToChange    = "Invalid settings payload"
	msgSettingsNotSaved   = "Failed to save settings"
	msgOverviewNotSaved   = "The overview settings could not be saved."
	msgTourNotSaved       = "Could not save tour progress"
	msgAcknowledgeMissing = "Explicit acknowledgement required"
)

func invalid(msg string) error { return fault.New(fault.InvalidValue, msg) }

// rows validates the changes and returns the values to store by key.
func (c Changes) rows() (map[string]jsontext.Value, error) {
	out := map[string]jsontext.Value{}
	choice := func(key string, v *string, set []string, msg string) error {
		if v == nil {
			return nil
		}
		if !in(set, *v) {
			return invalid(msg)
		}
		out[key] = marshalValue(*v)
		return nil
	}
	for _, f := range []struct {
		key string
		v   *string
		set []string
		msg string
	}{
		{keyStartPage, c.StartPage, StartPages, msgInvalidStartPage},
		{keyOverviewLayout, c.OverviewLayout, OverviewLayouts, msgInvalidLayout},
		{keyOverviewReachability, c.OverviewReachability, OverviewReachabilityMode, msgInvalidReach},
		{keyTheme, c.Theme, Themes, msgInvalidTheme},
		{keyDisconnectAction, c.DisconnectSessionAction, DisconnectSessionActions, msgInvalidDisconnect},
	} {
		if err := choice(f.key, f.v, f.set, f.msg); err != nil {
			return nil, err
		}
	}
	if c.TerminalAppearance != nil {
		if !ValidTerminalAppearance(c.TerminalAppearance) {
			return nil, invalid(msgInvalidAppearance)
		}
		out[keyTerminalAppearance] = c.TerminalAppearance
	}
	if c.SyncTerminalDirectory != nil {
		out[keySyncTerminalDir] = marshalValue(*c.SyncTerminalDirectory)
	}
	if c.ConfirmSessionClose != nil {
		out[keyConfirmSessionClose] = marshalValue(*c.ConfirmSessionClose)
	}
	if c.SessionDurationMinutes != nil {
		if !slices.Contains(SessionDurations, *c.SessionDurationMinutes) {
			return nil, invalid(msgInvalidDuration)
		}
		out[keySessionDuration] = marshalValue(*c.SessionDurationMinutes)
	}
	if c.OverviewPanels != nil {
		if !ValidOverviewPanels(c.OverviewPanels) {
			return nil, invalid(msgInvalidPanels)
		}
		out[keyOverviewPanels] = c.OverviewPanels
	}
	if c.OverviewDismissed != nil {
		if !ValidOverviewDismissed(c.OverviewDismissed) {
			return nil, invalid(msgInvalidDismissed)
		}
		out[keyOverviewDismissed] = c.OverviewDismissed
	}
	if c.Tour != nil {
		if !in(TourStates, *c.Tour) {
			return nil, invalid(msgInvalidTourState)
		}
		out[keyIntroTour] = marshalValue(*c.Tour)
		out[keyIntroTourV3Ack] = marshalValue(*c.Tour == "completed")
	}
	if len(out) == 0 {
		return nil, fault.New(fault.InvalidRequest, msgNothingToChange)
	}
	return out, nil
}
