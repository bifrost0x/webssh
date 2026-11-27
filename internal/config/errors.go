package config

import "fmt"

// Error is a configuration the Python release refuses to start with, or a
// value the Go release refuses. Message is the operator-facing text; for
// values the Python release rejects it is the Python message.
type Error struct {
	// Variable names the environment variable at fault, when there is one.
	Variable string
	Message  string
}

func (e *Error) Error() string { return e.Message }

func configError(variable, message string) error {
	return &Error{Variable: variable, Message: message}
}

// WarningKind classifies a startup warning.
type WarningKind string

const (
	// WarnPython repeats a warning the Python release prints for the same
	// configuration.
	WarnPython WarningKind = "python"
	// WarnInfo repeats an informational line of the Python release.
	WarnInfo WarningKind = "info"
	// WarnSecurity repeats a compatibility warning of the Python release's
	// homelab profile (SECURITY_CONFIG_WARNINGS).
	WarnSecurity WarningKind = "security"
	// WarnQuirk marks a value that keeps its Python meaning although it is
	// written in an unusual way, for example " true", which counts as
	// false (decision D-14).
	WarnQuirk WarningKind = "quirk"
	// WarnObsolete marks a variable that has no meaning in the Go release,
	// for example the Gunicorn settings (decision D-16).
	WarnObsolete WarningKind = "obsolete"
	// WarnProxy and WarnOrigin explain the effect of the proxy and origin
	// settings in the Go release (decisions D-19 and D-20).
	WarnProxy  WarningKind = "proxy"
	WarnOrigin WarningKind = "origin"
	// WarnTimeZone reports a TZ value the Go runtime cannot load.
	WarnTimeZone WarningKind = "timezone"
	// WarnSecret reports how the application secret was found.
	WarnSecret WarningKind = "secret"
)

// Warning is one startup message for the log. It never contains secret
// values.
type Warning struct {
	Kind     WarningKind
	Variable string
	Message  string
}

func (w Warning) String() string {
	if w.Variable == "" {
		return fmt.Sprintf("%s: %s", w.Kind, w.Message)
	}
	return fmt.Sprintf("%s: %s: %s", w.Kind, w.Variable, w.Message)
}
