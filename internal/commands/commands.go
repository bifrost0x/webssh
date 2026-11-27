package commands

import (
	"context"
	"encoding/json/jsontext"
	"fmt"
	"slices"

	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/store"
)

// Byte limits of one command (app/command_storage_policy.py).
const (
	maxCommandIDBytes   = 128
	maxDescriptionBytes = 16 << 10
	maxCategoryBytes    = 256
	maxOSValueBytes     = 128
)

// List is get_all_commands: the built-in templates, then the user's
// commands, each with isSystem and userId, optionally filtered by an
// operating system. osFilter is the raw os_filter of the request.
func (l *Library) List(ctx context.Context, userID int64, osFilter jsontext.Value) ([]jsontext.Value, error) {
	filterValue, _ := decode(osFilter)
	filter, isText := filterValue.(string)
	if truthy(filterValue) && !isText {
		return nil, invalid("Failed to load commands")
	}
	var user []jsontext.Value
	err := l.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		user, err = load(ctx, tx, commandTable, userID)
		return err
	})
	if err != nil {
		return nil, storageError(err, "Failed to load commands")
	}
	system, err := SystemCommands()
	if err != nil {
		return nil, err
	}
	out := system
	for _, rec := range user {
		members, ok := pyjson.Members(rec)
		if !ok {
			continue
		}
		members = pyjson.Set(members, "isSystem", jsontext.Value("false"))
		members = pyjson.Set(members, "userId", jsontext.Value(fmt.Sprint(userID)))
		out = append(out, pyjson.Object(members))
	}
	if filter == "" {
		return out, nil
	}
	want := lowerOS(filter)
	return slices.DeleteFunc(out, func(rec jsontext.Value) bool {
		v, _ := decode(rec)
		m, _ := v.(map[string]any)
		list, present := m["os"].([]any)
		if _, has := m["os"]; !has {
			return false // os defaults to ["all"]
		}
		if !present {
			return true
		}
		for _, o := range list {
			if s, ok := o.(string); ok && (s == "all" || lowerOS(s) == want) {
				return false
			}
		}
		return true
	}), nil
}

// commandInput is the client-controlled half of a command.
type commandInput struct {
	name, command, parameters, description, category string
	os                                               []any
}

// readCommandInput applies the handler checks of add_command and
// update_command: the required members, then valid_user_command_input.
func readCommandInput(req protocol.CommandSave, update bool) (commandInput, any, error) {
	values := map[string]any{}
	for name, raw := range map[string]jsontext.Value{"command_id": req.CommandID, "name": req.Name,
		"command": req.Command, "parameters": req.Parameters, "description": req.Description,
		"os": req.OS, "category": req.Category} {
		if v, ok := decode(raw); ok {
			values[name] = v
		}
	}
	defaults := map[string]any{"parameters": "", "os": []any{"all"}, "category": "custom"}
	for name, d := range defaults {
		if _, ok := values[name]; !ok {
			values[name] = d
		}
	}
	required := []string{"name", "command", "description"}
	msg := "Name, command, and description are required"
	if update {
		required = append([]string{"command_id"}, required...)
		msg = "Command ID, name, command, and description are required"
	}
	for _, name := range required {
		if !truthy(values[name]) {
			return commandInput{}, nil, invalid(msg)
		}
	}
	var in commandInput
	var ok [6]bool
	in.name, ok[0] = values["name"].(string)
	in.command, ok[1] = values["command"].(string)
	in.parameters, ok[2] = values["parameters"].(string)
	in.description, ok[3] = values["description"].(string)
	in.category, ok[4] = values["category"].(string)
	in.os, ok[5] = values["os"].([]any)
	for _, o := range in.os {
		if _, isText := o.(string); !isText {
			ok[5] = false
		}
	}
	if slices.Contains(ok[:], false) {
		return commandInput{}, nil, invalid("Invalid command data")
	}
	if in.category == "" {
		in.category = "custom"
	}
	return in, values["command_id"], nil
}

// validateCommand is validate_user_command against the stored record it
// replaces (nil for a new command).
func (l *Library) validateCommand(rec, legacy map[string]any) error {
	if err := boundedText(rec["id"], maxCommandIDBytes, "command id", legacy["id"]); err != nil {
		return err
	}
	for _, f := range []struct {
		name  string
		limit int
		label string
	}{
		{"name", MaxCommandNameBytes, "command name"},
		{"command", MaxCommandBytes, "command text"},
		{"parameters", MaxCommandBytes, "command parameters"},
		{"description", maxDescriptionBytes, "command description"},
		{"category", maxCategoryBytes, "command category"},
	} {
		v, ok := rec[f.name]
		if !ok {
			v = ""
		}
		if err := boundedText(v, f.limit, f.label, legacy[f.name]); err != nil {
			return err
		}
	}
	values, _ := rec["os"].([]any)
	old, _ := legacy["os"].([]any)
	if len(values) > l.Limits.withDefaults().MaxOSEntries && len(values) > len(old) {
		return quota("too many command operating systems")
	}
	for i, v := range values {
		var previous any
		if i < len(old) {
			previous = old[i]
		}
		if err := boundedText(v, maxOSValueBytes, "command operating system", previous); err != nil {
			return err
		}
	}
	return nil
}

// saveCommands writes the user's commands after the storage limits
// (save_user_commands).
func (l *Library) saveCommands(ctx context.Context, tx *store.Tx, userID int64, current, next []jsontext.Value) error {
	sets, err := load(ctx, tx, setTable, userID)
	if err != nil {
		return err
	}
	if err := l.transition(commandsDocSize(next), storedSize(current, commandsDocSize), len(next), len(current),
		l.Limits.withDefaults().MaxCommands, storedSize(sets, setsDocSize)); err != nil {
		return err
	}
	return replace(ctx, tx, commandTable, userID, next)
}

// Add is add_user_command.
func (l *Library) Add(ctx context.Context, userID int64, req protocol.CommandSave) (jsontext.Value, error) {
	in, _, err := readCommandInput(req, false)
	if err != nil {
		return nil, err
	}
	os := make([]string, len(in.os))
	for i, o := range in.os {
		os[i] = o.(string)
	}
	rec := object(
		member("id", rawString(l.newID())),
		member("name", rawString(in.name)),
		member("command", rawString(in.command)),
		member("parameters", rawString(in.parameters)),
		member("description", rawString(in.description)),
		member("os", rawValue(os)),
		member("category", rawString(in.category)),
		member("isSystem", jsontext.Value("false")),
		member("userId", jsontext.Value(fmt.Sprint(userID))),
		member("createdAt", rawString(isoNaive(l.now()))),
	)
	decoded, _ := decode(rec)
	if err := l.validateCommand(decoded.(map[string]any), nil); err != nil {
		return nil, err
	}
	err = l.DB.Write(ctx, func(tx *store.Tx) error {
		current, err := load(ctx, tx, commandTable, userID)
		if err != nil {
			return err
		}
		return l.saveCommands(ctx, tx, userID, current, append(slices.Clone(current), rec))
	})
	if err != nil {
		return nil, storageError(err, "Failed to add command")
	}
	return rec, nil
}

// Update is update_user_command: the stored record keeps its other
// members and their order.
func (l *Library) Update(ctx context.Context, userID int64, req protocol.CommandSave) (jsontext.Value, error) {
	in, id, err := readCommandInput(req, true)
	if err != nil {
		return nil, err
	}
	var saved jsontext.Value
	err = l.DB.Write(ctx, func(tx *store.Tx) error {
		current, err := load(ctx, tx, commandTable, userID)
		if err != nil {
			return err
		}
		// An id that is not text matches no stored command.
		index := slices.IndexFunc(current, func(rec jsontext.Value) bool {
			stored, ok := recordID(rec)
			return ok && stored == id
		})
		if index < 0 {
			return errCommandNotFound
		}
		members, _ := pyjson.Members(current[index])
		for _, m := range []pyjson.Member{
			member("name", rawString(in.name)), member("command", rawString(in.command)),
			member("parameters", rawString(in.parameters)), member("description", rawString(in.description)),
			member("os", rawValue(in.os)), member("category", rawString(in.category)),
		} {
			members = pyjson.Set(members, m.Name, m.Value)
		}
		updated := pyjson.Object(members)
		legacy, _ := decode(current[index])
		next, _ := decode(updated)
		if err := l.validateCommand(next.(map[string]any), legacy.(map[string]any)); err != nil {
			return err
		}
		all := slices.Clone(current)
		all[index] = updated
		saved = updated
		return l.saveCommands(ctx, tx, userID, current, all)
	})
	if err != nil {
		return nil, storageError(err, "Failed to save command")
	}
	return saved, nil
}

// Delete is delete_user_command: a command that a set or a saved host
// uses stays, and the refusal names at most 20 of the users.
func (l *Library) Delete(ctx context.Context, userID int64, commandIDValue jsontext.Value) (string, error) {
	v, _ := decode(commandIDValue)
	if !truthy(v) {
		return "", invalid("Command ID required")
	}
	id, isText := v.(string)
	err := l.DB.Write(ctx, func(tx *store.Tx) error {
		sets, err := load(ctx, tx, setTable, userID)
		if err != nil {
			return err
		}
		var usages []Usage
		count := 0
		kinds := map[string]bool{}
		for _, rec := range sets {
			if isText && setUsesCommand(rec, id) {
				count++
				kinds["command_set"] = true
				if len(usages) < MaxReferencedSetsShown {
					d, _ := decode(rec)
					m, _ := d.(map[string]any)
					usages = append(usages, Usage{ID: safeReferenceName(m["id"]), Name: safeReferenceName(m["name"]), Type: "command_set"})
				}
			}
		}
		profiles, err := l.commandUsages(ctx, tx, userID, id, isText)
		if err != nil {
			return err
		}
		for _, u := range profiles {
			count++
			kinds["profile"] = true
			if len(usages) < MaxReferencedSetsShown {
				usages = append(usages, Usage{ID: safeReferenceName(u.ID), Name: safeReferenceName(u.Name), Type: "profile"})
			}
		}
		if count > 0 {
			return inUse("Command", count, kinds, usageMaps(usages), len(usages))
		}
		current, err := load(ctx, tx, commandTable, userID)
		if err != nil {
			return err
		}
		remaining := slices.DeleteFunc(slices.Clone(current), func(rec jsontext.Value) bool {
			stored, ok := recordID(rec)
			return ok && isText && stored == id
		})
		if len(remaining) == len(current) {
			return errCommandNotFound
		}
		return l.saveCommands(ctx, tx, userID, current, remaining)
	})
	if err != nil {
		return "", storageError(err, "Failed to delete command")
	}
	return id, nil
}

// setUsesCommand reports a library step of the set that names id.
func setUsesCommand(rec jsontext.Value, id string) bool {
	v, _ := decode(rec)
	m, _ := v.(map[string]any)
	steps, _ := m["steps"].([]any)
	for _, s := range steps {
		step, ok := s.(map[string]any)
		if ok && step["type"] == string(StepLibrary) && step["command_id"] == id {
			return true
		}
	}
	return false
}
