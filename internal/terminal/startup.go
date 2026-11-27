package terminal

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// Commands is the command library as the post-connect behaviour uses it
// (provided by internal/commands). Command returns the text and the
// stored parameters of a command of owner; ResolveSet the startup text of
// a set of owner without values, which fails for a parameterised set.
// Both fail with fault.NotFound for an unknown or foreign id and carry a
// text that is safe to show.
type Commands interface {
	Command(ctx context.Context, owner int64, commandID string) (command, parameters string, err error)
	ResolveSet(ctx context.Context, owner int64, setID string) (string, error)
}

// Post-connect modes (VALID_MODES of app/post_connect_manager.py).
const (
	startupNone     = "none"
	startupFreeText = "free_text"
	startupCommand  = "command"
	startupSet      = "command_set"
)

// maxStartupRunes is MAX_STARTUP_COMMANDS_LENGTH; the byte bound
// (MAX_STARTUP_COMMANDS_UTF8_BYTES) is protocol.MaxStartupBytes.
const maxStartupRunes = 4096

// inferMode is infer_mode: the explicit mode, else the first reference
// that is set.
func inferMode(s *protocol.Startup) string {
	switch {
	case s.Mode != "":
		return s.Mode
	case s.CommandSetID != "":
		return startupSet
	case s.CommandID != "":
		return startupCommand
	case s.Commands != "":
		return startupFreeText
	}
	return startupNone
}

// checkStartupMode applies the mode and conflict checks that run before
// anything is resolved (Python checks them before it dials as well).
func checkStartupMode(s *protocol.Startup) (string, error) {
	if s == nil {
		return startupNone, nil
	}
	mode := inferMode(s)
	switch mode {
	case startupNone, startupFreeText, startupCommand, startupSet:
	default:
		return "", invalid("Invalid post-connect command mode")
	}
	if (mode == startupCommand && s.CommandSetID != "") || (mode == startupSet && s.CommandID != "") ||
		(mode == startupFreeText && (s.CommandID != "" || s.CommandSetID != "")) {
		return "", invalid("Conflicting post-connect command configuration")
	}
	return mode, nil
}

// normalizeStartup is normalize_startup_commands: at most 4096 code
// points, no NUL, valid UTF-8, line breaks as LF.
func normalizeStartup(v string) (string, error) {
	switch {
	case utf8.RuneCountInString(v) > maxStartupRunes:
		return "", invalid("Startup commands must not exceed 4096 characters")
	case strings.IndexByte(v, 0) >= 0:
		return "", invalid("Startup commands must not contain NUL bytes")
	case !utf8.ValidString(v):
		return "", invalid("Startup commands must be valid UTF-8")
	}
	return strings.ReplaceAll(strings.ReplaceAll(v, "\r\n", "\n"), "\r", "\n"), nil
}

// validateParameters is validate_command_parameters.
func validateParameters(v string) error {
	switch {
	case utf8.RuneCountInString(v) > maxStartupRunes:
		return invalid("Command parameters must not exceed 4096 characters")
	case !utf8.ValidString(v):
		return invalid("Command parameters must be valid UTF-8")
	case len(v) > protocol.MaxStartupBytes:
		return invalid("Command parameters exceed the UTF-8 byte limit")
	case strings.IndexByte(v, 0) >= 0:
		return invalid("Commands cannot contain NUL bytes")
	}
	return nil
}

// resolveStartup is resolve_configuration: the startup text of the
// request, normalized, or "" for none. A command or set is read from the
// owner's library at this moment; without a library they are not
// available in this build.
func (m *Manager) resolveStartup(ctx context.Context, owner int64, s *protocol.Startup) (string, error) {
	mode, err := checkStartupMode(s)
	if err != nil {
		return "", err
	}
	switch mode {
	case startupNone:
		return "", nil
	case startupFreeText:
		return normalizeStartup(s.Commands)
	}
	if m.commands == nil {
		return "", fault.New(fault.NotAvailableInPreview, "")
	}
	if mode == startupSet {
		if s.CommandSetID == "" {
			return "", fault.New(fault.NotFound, "Command set not found")
		}
		text, err := m.commands.ResolveSet(ctx, owner, s.CommandSetID)
		if err != nil {
			return "", err
		}
		return normalizeStartup(text)
	}
	if s.CommandID == "" {
		return "", fault.New(fault.NotFound, "Command not found")
	}
	command, params, err := m.commands.Command(ctx, owner, s.CommandID)
	if err != nil {
		return "", err
	}
	return composeCommand(command, params, s.ParametersOverride)
}

// composeCommand is _resolve_command: the override, when given and not
// null, replaces the stored parameters; a non-empty parameter text is
// appended after one space.
func composeCommand(command, stored string, override *string) (string, error) {
	params := stored
	if override != nil {
		params = *override
	}
	if err := validateParameters(params); err != nil {
		return "", err
	}
	if params != "" {
		command += " " + params
	}
	return normalizeStartup(command)
}

// terminalInput is to_terminal_input with the Enter the connect path
// adds: line feeds become carriage returns, trailing ones are dropped and
// one Enter ends the text.
func terminalInput(text string) []byte {
	return []byte(strings.TrimRight(strings.ReplaceAll(text, "\n", "\r"), "\r") + "\r")
}
