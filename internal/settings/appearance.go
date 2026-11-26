package settings

import (
	"encoding/json/jsontext"
	"regexp"
)

// Terminal appearance overrides (app/terminal_appearance.py). They are
// strict and free of CSS: an empty object follows the application theme.

var (
	appearanceColour = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)
	appearanceFont   = regexp.MustCompile(`^[A-Za-z0-9 _-]{1,64}$`)
)

// ValidTerminalAppearance reports whether v is an object of known,
// well-typed overrides.
func ValidTerminalAppearance(v jsontext.Value) bool {
	members, ok := asObject(v)
	if !ok {
		return false
	}
	for _, m := range members {
		if !validAppearanceMember(m.name, m.value) {
			return false
		}
	}
	return true
}

func validAppearanceMember(name string, v jsontext.Value) bool {
	switch name {
	case "background", "foreground", "cursor_color", "selection_background":
		if isNull(v) {
			return true
		}
		s, ok := asString(v)
		return ok && appearanceColour.MatchString(s)
	case "font_family":
		s, ok := asString(v)
		return ok && appearanceFont.MatchString(s)
	case "font_size":
		if isNull(v) {
			return true
		}
		n, ok := asInt(v)
		return ok && n >= 8 && n <= 32
	case "line_height":
		f, ok := asFinite(v)
		return ok && f >= 1 && f <= 2
	case "letter_spacing":
		f, ok := asFinite(v)
		return ok && f >= -1 && f <= 3
	case "font_weight":
		s, ok := asString(v)
		return ok && (s == "normal" || s == "bold")
	case "background_opacity":
		n, ok := asInt(v)
		return ok && n >= 0 && n <= 100
	case "cursor_style":
		s, ok := asString(v)
		return ok && (s == "block" || s == "underline" || s == "bar")
	case "cursor_blink":
		_, ok := asBool(v)
		return ok
	}
	return false
}
