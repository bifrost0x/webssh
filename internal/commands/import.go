package commands

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"strings"

	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/store"
)

// The migration of E26 and E27 takes the stores of the Python release
// over record by record, verbatim and in order. A store Python itself
// refuses to read (_valid_commands, _valid_command_set_document) stops
// the migration; the page would show it as damaged.

// ErrInvalidRecord is a stored record the Python release rejects.
var ErrInvalidRecord = errors.New("commands: record the Python release does not accept")

// validStoredCommand is _valid_command of app/command_manager.py.
func validStoredCommand(rec jsontext.Value) bool {
	v, _ := decode(rec)
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	for _, f := range []string{"id", "name", "command"} {
		if _, ok := m[f].(string); !ok {
			return false
		}
	}
	for _, f := range []string{"parameters", "description", "category", "createdAt"} {
		if x, present := m[f]; present {
			if _, ok := x.(string); !ok {
				return false
			}
		}
	}
	if os, present := m["os"]; present {
		list, ok := os.([]any)
		if !ok {
			return false
		}
		for _, o := range list {
			if _, ok := o.(string); !ok {
				return false
			}
		}
	}
	if x, present := m["isSystem"]; present {
		if _, ok := x.(bool); !ok {
			return false
		}
	}
	// userId is null or an integer literal (type int in Python).
	if raw, present := pyjson.Get(rec, "userId"); present && raw.Kind() != 'n' {
		if raw.Kind() != '0' || strings.ContainsAny(string(raw), ".eE") {
			return false
		}
	}
	return true
}

// validStoredSet is _valid_command_set of app/command_set_manager.py.
func validStoredSet(rec jsontext.Value) bool {
	v, _ := decode(rec)
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	if _, ok := m["id"].(string); !ok {
		return false
	}
	if _, ok := m["name"].(string); !ok {
		return false
	}
	steps, ok := m["steps"].([]any)
	if !ok {
		return false
	}
	for _, s := range steps {
		if !validStoredStep(s) {
			return false
		}
	}
	for _, f := range []string{"description", "created_at", "updated_at"} {
		if x, present := m[f]; present {
			if _, ok := x.(string); !ok {
				return false
			}
		}
	}
	if x, present := m["use_sudo"]; present {
		if _, ok := x.(bool); !ok {
			return false
		}
	}
	return !truthy(m["parameters"]) || checkParameterSet(m) == ""
}

// validStoredStep is _valid_step.
func validStoredStep(v any) bool {
	step, ok := v.(map[string]any)
	if !ok {
		return false
	}
	switch step["type"] {
	case string(StepInline):
		_, ok := step["command"].(string)
		return ok
	case string(StepArgv):
		argv, ok := step["argv"].([]any)
		if !ok {
			return false
		}
		for _, a := range argv {
			if _, ok := a.(string); !ok {
				return false
			}
		}
		return true
	case string(StepLibrary):
		if _, ok := step["command_id"].(string); !ok {
			return false
		}
		o, present := step["parameters_override"]
		if !present || o == nil {
			return true
		}
		_, ok := o.(string)
		return ok
	}
	return false
}

// ImportTx stores the migrated commands and sets of one user. The
// commands are the records of commands.json and the sets those of
// command_sets.json, as Python stored them.
func ImportTx(ctx context.Context, tx *store.Tx, userID int64, cmds, sets []jsontext.Value) error {
	for i, rec := range cmds {
		if !validStoredCommand(rec) {
			return fmt.Errorf("commands.json record %d: %w", i, ErrInvalidRecord)
		}
	}
	for i, rec := range sets {
		if !validStoredSet(rec) {
			return fmt.Errorf("command_sets.json record %d: %w", i, ErrInvalidRecord)
		}
	}
	if err := replace(ctx, tx, commandTable, userID, cmds); err != nil {
		return err
	}
	return replace(ctx, tx, setTable, userID, sets)
}

// StoredTx returns the stored commands and sets of one user in order.
func StoredTx(ctx context.Context, tx *store.Tx, userID int64) (cmds, sets []jsontext.Value, err error) {
	if cmds, err = load(ctx, tx, commandTable, userID); err != nil {
		return nil, nil, err
	}
	sets, err = load(ctx, tx, setTable, userID)
	return cmds, sets, err
}

// ResolveStoredTx is the preview of one stored set as the library lists
// it: the startup text, or the message why it has none. The migration
// compares it with the preview of the Python release.
func ResolveStoredTx(ctx context.Context, tx *store.Tx, userID int64, setID string, sudo bool) (string, string, error) {
	s, err := readSnapshot(ctx, tx, userID)
	if err != nil {
		return "", "", err
	}
	i := s.find(setID)
	if i < 0 {
		return "", "", errSetNotFound
	}
	text, msg := resolveLoaded(s.decoded[i], s.idx, sudo)
	return text, msg, nil
}
