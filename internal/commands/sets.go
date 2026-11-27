package commands

import (
	"context"
	"encoding/json/jsontext"
	"slices"

	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/store"
)

// setFields are the members a save replaces; every other stored member
// is kept (_COMMAND_SET_FIELDS).
var setFields = []string{"id", "name", "description", "use_sudo", "steps", "created_at", "updated_at", "parameters"}

// setPayload is the save request as Python's dict.
func setPayload(req protocol.CommandSetSave) map[string]any {
	p := map[string]any{}
	for name, raw := range map[string]jsontext.Value{"id": req.ID, "name": req.Name, "description": req.Description,
		"use_sudo": req.UseSudo, "parameters": req.Parameters, "steps": req.Steps} {
		if v, ok := decode(raw); ok {
			p[name] = v
		}
	}
	return p
}

// validated is the stored half of a set that passed _validate_payload.
type validated struct {
	id          any // string or nil
	name        string
	description string
	useSudo     bool
	steps       []jsontext.Value
	parameters  jsontext.Value
}

func (v validated) members(id jsontext.Value) []pyjson.Member {
	return []pyjson.Member{
		member("id", id),
		member("name", rawString(v.name)),
		member("description", rawString(v.description)),
		member("use_sudo", rawValue(v.useSudo)),
		member("steps", pyjson.Array(v.steps)),
		member("parameters", v.parameters),
	}
}

// validatePayload is _validate_payload against the user's stored sets.
func (l *Library) validatePayload(p map[string]any, sets []map[string]any, idx commandIndex) (validated, error) {
	rawName, _ := p["name"].(string)
	name := pyStrip(rawName)
	if name == "" {
		return validated{}, invalid("Command set name is required")
	}
	if runeLen(name) > MaxSetNameRunes {
		return validated{}, invalid("Command set name must be 128 characters or fewer")
	}
	description, ok := "", true
	if v, present := p["description"]; present {
		if description, ok = v.(string); !ok {
			return validated{}, invalid("Command set description must be text")
		}
	}
	useSudo := false
	if v, present := p["use_sudo"]; present {
		if useSudo, ok = v.(bool); !ok {
			return validated{}, invalid("Command set sudo option must be a boolean")
		}
	}
	id := p["id"]
	if _, isText := id.(string); id != nil && !isText {
		return validated{}, invalid("Invalid command set id")
	}
	var legacy map[string]any
	for _, s := range sets {
		storedName, _ := s["name"].(string)
		if s["id"] != id && fold(storedName) == fold(name) {
			return validated{}, invalid("A command set with this name already exists")
		}
		if legacy == nil && s["id"] == id {
			legacy = s
		}
	}
	idText, _ := id.(string)
	if err := l.validateSetBytes(map[string]any{"id": idText, "name": name, "description": pyStrip(description),
		"steps": p["steps"]}, legacy); err != nil {
		return validated{}, err
	}
	params, present := p["parameters"]
	if !present {
		params = []any{}
	}
	list, isList := params.([]any)
	if !isList {
		return validated{}, invalid("Command parameters must be a list")
	}
	out := validated{id: id, name: name, description: pyStrip(description), useSudo: useSudo, parameters: rawValue(list)}
	if len(list) > 0 {
		if msg := checkParameterSet(p); msg != "" {
			return validated{}, invalid(msg)
		}
		for _, s := range p["steps"].([]any) {
			argv := s.(map[string]any)["argv"]
			out.steps = append(out.steps, object(member("type", rawString("argv")), member("argv", rawValue(argv))))
		}
		return out, nil
	}
	steps, _, msg := normalizeSteps(p["steps"], idx)
	if msg != "" {
		return validated{}, invalid(msg)
	}
	out.steps = steps
	return out, nil
}

// snapshot is the user's commands and sets of one transaction.
type snapshot struct {
	commands, sets []jsontext.Value
	decoded        []map[string]any
	idx            commandIndex
}

func readSnapshot(ctx context.Context, tx *store.Tx, userID int64) (snapshot, error) {
	var s snapshot
	var err error
	if s.commands, err = load(ctx, tx, commandTable, userID); err != nil {
		return s, err
	}
	if s.sets, err = load(ctx, tx, setTable, userID); err != nil {
		return s, err
	}
	for _, rec := range s.sets {
		v, _ := decode(rec)
		m, _ := v.(map[string]any)
		s.decoded = append(s.decoded, m)
	}
	s.idx, err = buildIndex(s.commands)
	return s, err
}

// find returns the index of the stored set with this id, or -1.
func (s snapshot) find(id any) int {
	if _, ok := id.(string); !ok {
		return -1
	}
	return slices.IndexFunc(s.decoded, func(m map[string]any) bool { return m["id"] == id })
}

// saveSets writes the user's sets after the storage limits
// (_save_command_sets).
func (l *Library) saveSets(ctx context.Context, tx *store.Tx, userID int64, s snapshot, next []jsontext.Value) error {
	if err := l.transition(setsDocSize(next), storedSize(s.sets, setsDocSize), len(next), len(s.sets),
		l.Limits.withDefaults().MaxSets, storedSize(s.commands, commandsDocSize)); err != nil {
		return err
	}
	return replace(ctx, tx, setTable, userID, next)
}

// Sets is load_command_sets_with_resolution: every stored set with its
// preview, resolved from the same snapshot of commands.
func (l *Library) Sets(ctx context.Context, userID int64) ([]jsontext.Value, error) {
	var s snapshot
	err := l.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		s, err = readSnapshot(ctx, tx, userID)
		return err
	})
	if err != nil {
		return nil, storageError(err, "Command set storage is unreadable")
	}
	out := make([]jsontext.Value, 0, len(s.sets))
	for i, rec := range s.sets {
		members, ok := pyjson.Members(rec)
		if !ok {
			continue
		}
		resolved, msg := resolveLoaded(s.decoded[i], s.idx, false)
		if msg != "" {
			members = pyjson.Set(members, "resolution_error", rawString(msg))
		} else {
			members = pyjson.Set(members, "resolved_command", rawString(resolved))
			if sudo, msg := resolveLoaded(s.decoded[i], s.idx, true); msg != "" {
				members = pyjson.Set(members, "sudo_resolution_error", rawString(msg))
			} else {
				members = pyjson.Set(members, "sudo_resolved_command", rawString(sudo))
			}
		}
		out = append(out, pyjson.Object(members))
	}
	return out, nil
}

// SaveSet is upsert_command_set: a new set gets an id, an update keeps
// the stored members the page does not send and created_at.
func (l *Library) SaveSet(ctx context.Context, userID int64, req protocol.CommandSetSave) (jsontext.Value, error) {
	p := setPayload(req)
	var result jsontext.Value
	err := l.DB.Write(ctx, func(tx *store.Tx) error {
		var err error
		result, err = l.saveSetTx(ctx, tx, userID, p)
		return err
	})
	if err != nil {
		return nil, storageError(err, "Failed to save command sets")
	}
	return result, nil
}

func (l *Library) saveSetTx(ctx context.Context, tx *store.Tx, userID int64, p map[string]any) (jsontext.Value, error) {
	if id, ok := p["id"].(string); ok && truthy(id) && truthy(p["parameters"]) {
		usages, err := l.setUsages(ctx, tx, userID, id, true)
		if err != nil {
			return nil, err
		}
		if len(usages) > 0 {
			return nil, invalid("Remove startup profile references before adding command parameters")
		}
	}
	s, err := readSnapshot(ctx, tx, userID)
	if err != nil {
		return nil, err
	}
	v, err := l.validatePayload(p, s.decoded, s.idx)
	if err != nil {
		return nil, err
	}
	now := rawString(isoUTC(l.now()))
	next := slices.Clone(s.sets)
	var result jsontext.Value
	if v.id != nil {
		index := s.find(v.id)
		if index < 0 {
			return nil, errSetNotFound
		}
		stored, _ := pyjson.Members(s.sets[index])
		var members []pyjson.Member
		for _, m := range stored {
			if !slices.Contains(setFields, m.Name) {
				members = append(members, m)
			}
		}
		members = append(members, v.members(rawValue(v.id))...)
		created := now
		for _, m := range stored {
			if m.Name == "created_at" {
				created = m.Value
			}
		}
		members = append(members, member("created_at", created), member("updated_at", now))
		result = pyjson.Object(members)
		next[index] = result
	} else {
		members := append(v.members(rawString(l.newID())), member("created_at", now), member("updated_at", now))
		result = pyjson.Object(members)
		next = append(next, result)
	}
	if err := l.saveSets(ctx, tx, userID, s, next); err != nil {
		return nil, err
	}
	return result, nil
}
