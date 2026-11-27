package commands

import (
	"context"
	"encoding/json/jsontext"

	"github.com/bifrost0x/webssh/internal/store"
)

// The provider API of the library (M2 contracts, "Commands and command
// sets"): the terminal resolves startup modes, the host context checks
// its references and the automation runs a set as a step. Every method
// reads one snapshot and works for the owner only; another user's set or
// command is not found.

func (l *Library) snapshot(ctx context.Context, userID int64) (snapshot, error) {
	var s snapshot
	err := l.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		s, err = readSnapshot(ctx, tx, userID)
		return err
	})
	if err != nil {
		return s, storageError(err, "Command set storage is unreadable")
	}
	return s, nil
}

// Resolve returns the text of one set of the user. Without values it is
// the startup text of a set without parameters (sudo as the set says, or
// always when sudo is true); a parameterised set then is refused, as it
// needs interactive launch. With values the set must be parameterised
// and every declared value must be given; the values are quoted as whole
// arguments and never stored.
func (l *Library) Resolve(ctx context.Context, userID int64, setID string, values map[string]string, sudo bool) (string, error) {
	s, err := l.snapshot(ctx, userID)
	if err != nil {
		return "", err
	}
	index := s.find(setID)
	if setID == "" || index < 0 {
		return "", errSetNotFound
	}
	set := s.decoded[index]
	if values == nil {
		text, msg := resolveLoaded(set, s.idx, sudo)
		if msg != "" {
			return "", invalid(msg)
		}
		return text, nil
	}
	given := make(map[string]any, len(values))
	for k, v := range values {
		given[k] = v
	}
	return resolveWithValues(set, given, true, sudo)
}

// resolveWithValues is resolve_parameters of one stored set.
func resolveWithValues(set map[string]any, values map[string]any, valuesObj, sudo bool) (string, error) {
	if msg := checkParameterSet(set); msg != "" {
		return "", invalid(msg)
	}
	steps, names := argvSteps(set)
	text, msg := resolveArgv(steps, names, values, valuesObj, sudo || set["use_sudo"] == true)
	if msg != "" {
		return "", invalid(msg)
	}
	return text, nil
}

// ResolveParameters is resolve_command_set_parameters with the raw members
// of the request: the preview of a parameterised set with values given
// at launch.
func (l *Library) ResolveParameters(ctx context.Context, userID int64, setID, values, useSudo jsontext.Value) (string, error) {
	sudoValue, present := decode(useSudo)
	sudo, isBool := sudoValue.(bool)
	if present && !isBool {
		return "", invalid("Invalid command parameter data")
	}
	idValue, _ := decode(setID)
	id, _ := idValue.(string)
	s, err := l.snapshot(ctx, userID)
	if err != nil {
		return "", err
	}
	index := s.find(id)
	if id == "" || index < 0 {
		return "", errSetNotFound
	}
	given, _ := decode(values)
	obj, isObj := given.(map[string]any)
	return resolveWithValues(s.decoded[index], obj, isObj, sudo)
}

// SetExists tells whether the user owns the set.
func (l *Library) SetExists(ctx context.Context, userID int64, setID string) (bool, error) {
	s, err := l.snapshot(ctx, userID)
	if err != nil {
		return false, err
	}
	return setID != "" && s.find(setID) >= 0, nil
}

// SetInfo describes one set of the user for a consumer that lists or
// checks sets (the automation shows them as steps).
type SetInfo struct {
	ID, Name string
	// Parameters are the declared names; a set with parameters runs only
	// with values (Resolve with values).
	Parameters []string
}

// SetInfo returns the set, or not_found.
func (l *Library) SetInfo(ctx context.Context, userID int64, setID string) (SetInfo, error) {
	s, err := l.snapshot(ctx, userID)
	if err != nil {
		return SetInfo{}, err
	}
	index := s.find(setID)
	if setID == "" || index < 0 {
		return SetInfo{}, errSetNotFound
	}
	set := s.decoded[index]
	info := SetInfo{ID: setID}
	info.Name, _ = set["name"].(string)
	params, _ := set["parameters"].([]any)
	for _, p := range params {
		if m, ok := p.(map[string]any); ok {
			if n, ok := m["name"].(string); ok {
				info.Parameters = append(info.Parameters, n)
			}
		}
	}
	return info, nil
}

// Command returns the text and the stored parameters of one command the
// user can use: one of the built-in templates or an own command
// (_get_owned_command).
func (l *Library) Command(ctx context.Context, userID int64, commandID string) (command, parameters string, err error) {
	s, err := l.snapshot(ctx, userID)
	if err != nil {
		return "", "", err
	}
	c, ok := s.idx[commandID]
	if commandID == "" || !ok {
		return "", "", errCommandNotFound
	}
	command = c["command"].(string)
	p, present := c["parameters"]
	if !present {
		return command, "", nil
	}
	text, isText := p.(string)
	if !isText {
		return "", "", invalid("Command parameters must be a string")
	}
	return command, text, nil
}

// CheckCommandTx is the command half of validate_configuration for a
// saved host, inside the transaction that saves it: the command exists
// for the user and its text with the parameters (the override when given
// and not null) is a valid startup text.
func (l *Library) CheckCommandTx(ctx context.Context, tx *store.Tx, userID int64, commandID, override jsontext.Value) error {
	s, err := readSnapshot(ctx, tx, userID)
	if err != nil {
		return err
	}
	idValue, _ := decode(commandID)
	id, _ := idValue.(string)
	c, ok := s.idx[id]
	if id == "" || !ok {
		return errCommandNotFound
	}
	params, present := c["parameters"]
	if !present {
		params = ""
	}
	if o, given := decode(override); given && o != nil {
		params = o
	}
	text, isText := params.(string)
	if !isText {
		return invalid("Command parameters must be a string")
	}
	if msg := validateCommandParameters(text); msg != "" {
		return invalid(msg)
	}
	line := c["command"].(string)
	if text != "" {
		line += " " + text
	}
	if _, msg := normalizeStartup(line); msg != "" {
		return invalid(msg)
	}
	return nil
}

// CheckSetTx is the set half of validate_configuration: the user owns
// the set and it has no parameters.
func (l *Library) CheckSetTx(ctx context.Context, tx *store.Tx, userID int64, setID jsontext.Value) error {
	s, err := readSnapshot(ctx, tx, userID)
	if err != nil {
		return err
	}
	idValue, _ := decode(setID)
	id, _ := idValue.(string)
	index := s.find(id)
	if id == "" || index < 0 {
		return errSetNotFound
	}
	if truthy(s.decoded[index]["parameters"]) {
		return invalid(msgInteractive)
	}
	return nil
}
