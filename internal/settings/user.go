package settings

import (
	"encoding/json/jsontext"
	"maps"
	"slices"
)

// User is the effective settings of one account: the stored values over
// the defaults of this release, read like get_user_settings of the
// Python release.
type User struct {
	Theme                string
	StartPage            string
	OverviewLayout       string
	OverviewReachability string
	// OverviewPanels are the stored placements that are still valid, in
	// the form the browser sent them; nil is the default layout.
	OverviewPanels    []jsontext.Value
	OverviewDismissed []string
	// TerminalAppearance is the stored override object, "{}" by default.
	TerminalAppearance      jsontext.Value
	ConfirmSessionClose     bool
	SyncTerminalDirectory   bool
	DisconnectSessionAction string
	SessionDurationMinutes  int
	// Tour is the stored state of the introduction tour, "" when unset.
	Tour             string
	TourAcknowledged bool

	// stored holds every stored value by key, also keys this release does
	// not act on.
	stored map[string]jsontext.Value
}

// defaultUser returns the settings of an account without stored values.
func defaultUser() User {
	return User{
		Theme:                   DefaultTheme,
		StartPage:               DefaultStartPage,
		OverviewLayout:          DefaultOverviewLayout,
		OverviewReachability:    DefaultOverviewReachability,
		OverviewDismissed:       []string{},
		TerminalAppearance:      jsontext.Value("{}"),
		ConfirmSessionClose:     DefaultConfirmSessionClose,
		SyncTerminalDirectory:   DefaultSyncTerminalDirectory,
		DisconnectSessionAction: DefaultDisconnectSessionAction,
		SessionDurationMinutes:  DefaultSessionDuration,
		stored:                  map[string]jsontext.Value{},
	}
}

// validStored reports whether a stored value of key loads, with the
// checks _valid_settings of the Python release applies to a settings file.
// Overview values are only type-checked; their entries are filtered on
// read. Unknown keys load whatever they hold.
func validStored(key string, v jsontext.Value) bool {
	switch key {
	case keyOverviewLayout:
		return validChoice(v, OverviewLayouts)
	case keyStartPage:
		return validChoice(v, StartPages)
	case keyOverviewReachability:
		return validChoice(v, OverviewReachabilityMode)
	case keyDisconnectAction:
		return validChoice(v, DisconnectSessionActions)
	case keyOverviewPanels:
		return isNull(v) || v.Kind() == '['
	case keyOverviewDismissed:
		return v.Kind() == '['
	case keyTheme:
		_, ok := asString(v)
		return ok
	case keySyncTerminalDir, keyConfirmSessionClose:
		_, ok := asBool(v)
		return ok
	case keyTerminalAppearance:
		return ValidTerminalAppearance(v)
	case keySessionDuration:
		n, ok := asInt(v)
		return ok && slices.Contains(SessionDurations, int(n))
	case keyRecoveryReviewedAt:
		// The Python release accepts "" or an ISO 8601 time with offset of
		// at most 64 characters. Only the import writes it, from a file
		// Python validated; the type and length are checked again here.
		s, ok := asString(v)
		return ok && len([]rune(s)) <= 64
	case legacyKeyNotepad, legacyKeyWorkspacePresets, legacyKeySchemaVersion:
		// Owned elsewhere; never stored here.
		return false
	}
	return true
}

func validChoice(v jsontext.Value, set []string) bool {
	s, ok := asString(v)
	return ok && in(set, s)
}

// buildUser applies stored values to the defaults. Every value has passed
// validStored when it was written; a value that no longer does is an error
// of the store, reported by the caller.
func buildUser(stored map[string]jsontext.Value) (User, bool) {
	u := defaultUser()
	for key, v := range stored {
		if !validStored(key, v) {
			return User{}, false
		}
	}
	u.stored = maps.Clone(stored)
	str := func(key string, dst *string) {
		if v, ok := stored[key]; ok {
			*dst, _ = asString(v)
		}
	}
	boolean := func(key string, dst *bool) {
		if v, ok := stored[key]; ok {
			*dst, _ = asBool(v)
		}
	}
	str(keyTheme, &u.Theme)
	str(keyStartPage, &u.StartPage)
	str(keyOverviewLayout, &u.OverviewLayout)
	str(keyOverviewReachability, &u.OverviewReachability)
	str(keyDisconnectAction, &u.DisconnectSessionAction)
	boolean(keyConfirmSessionClose, &u.ConfirmSessionClose)
	boolean(keySyncTerminalDir, &u.SyncTerminalDirectory)
	if v, ok := stored[keyOverviewPanels]; ok {
		u.OverviewPanels = knownPanels(v)
	}
	if v, ok := stored[keyOverviewDismissed]; ok {
		u.OverviewDismissed = knownDismissed(v)
	}
	if v, ok := stored[keyTerminalAppearance]; ok {
		u.TerminalAppearance = v
	}
	if v, ok := stored[keySessionDuration]; ok {
		n, _ := asInt(v)
		u.SessionDurationMinutes = int(n)
	}
	// The tour state is not validated by the Python release; only the
	// values the tour route writes count.
	if v, ok := stored[keyIntroTour]; ok {
		if s, ok := asString(v); ok && in(TourStates, s) {
			u.Tour = s
		}
	}
	if v, ok := stored[keyIntroTourV3Ack]; ok {
		u.TourAcknowledged = string(v) == "true"
	}
	return u, true
}

// overviewPanelsValue is the effective arrangement as JSON: null or the
// kept placements.
func (u User) overviewPanelsValue() jsontext.Value {
	if len(u.OverviewPanels) == 0 {
		return jsontext.Value("null")
	}
	return joinArray(u.OverviewPanels)
}

func joinArray(items []jsontext.Value) jsontext.Value {
	out := []byte{'['}
	for i, item := range items {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, item...)
	}
	return append(out, ']')
}

// Document returns the effective settings as one object, the "settings"
// member of the preferences response: every key with a default, then
// every other stored key verbatim. The notepad and the workspace presets
// are not settings in this release and are not part of it.
func (u User) Document() map[string]jsontext.Value {
	doc := maps.Clone(u.stored)
	doc[keyTheme] = marshalValue(u.Theme)
	doc[keyStartPage] = marshalValue(u.StartPage)
	doc[keyOverviewLayout] = marshalValue(u.OverviewLayout)
	doc[keyOverviewReachability] = marshalValue(u.OverviewReachability)
	doc[keyOverviewPanels] = u.overviewPanelsValue()
	doc[keyOverviewDismissed] = marshalValue(u.OverviewDismissed)
	doc[keyTerminalAppearance] = u.TerminalAppearance
	doc[keyConfirmSessionClose] = marshalValue(u.ConfirmSessionClose)
	doc[keySyncTerminalDir] = marshalValue(u.SyncTerminalDirectory)
	doc[keyDisconnectAction] = marshalValue(u.DisconnectSessionAction)
	doc[keySessionDuration] = marshalValue(u.SessionDurationMinutes)
	return doc
}
