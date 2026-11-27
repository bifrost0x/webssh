package commands

import (
	"context"
	"encoding/json/jsontext"
	"slices"
	"strconv"

	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/store"
)

// DuplicateSet is duplicate_command_set: a copy named "<name> Copy" (or
// "Copy 2", "Copy 3", ...) with a new id; unknown members are not copied.
func (l *Library) DuplicateSet(ctx context.Context, userID int64, setID jsontext.Value) (jsontext.Value, error) {
	id, _ := decode(setID)
	var result jsontext.Value
	err := l.DB.Write(ctx, func(tx *store.Tx) error {
		s, err := readSnapshot(ctx, tx, userID)
		if err != nil {
			return err
		}
		index := s.find(id)
		if index < 0 {
			return errSetNotFound
		}
		source := s.decoded[index]
		names := map[string]bool{}
		for _, m := range s.decoded {
			n, _ := m["name"].(string)
			names[fold(n)] = true
		}
		name, _ := source["name"].(string)
		var candidate string
		for n := 1; ; n++ {
			extra := " Copy"
			if n > 1 {
				extra = " Copy " + strconv.Itoa(n)
			}
			runes := []rune(name)
			candidate = string(runes[:min(len(runes), max(0, MaxSetNameRunes-runeLen(extra)))]) + extra
			if !names[fold(candidate)] {
				break
			}
		}
		now := rawString(isoUTC(l.now()))
		description, ok := source["description"]
		if !ok {
			description = ""
		}
		steps, ok := source["steps"]
		if !ok {
			steps = []any{}
		}
		params, ok := source["parameters"]
		if !ok {
			params = []any{}
		}
		stored, _ := pyjson.Members(s.sets[index])
		raw := func(name string, fallback any) jsontext.Value {
			for _, m := range stored {
				if m.Name == name {
					return m.Value
				}
			}
			return rawValue(fallback)
		}
		result = object(
			member("id", rawString(l.newID())),
			member("name", rawString(candidate)),
			member("description", raw("description", description)),
			member("use_sudo", rawValue(source["use_sudo"] == true)),
			member("steps", raw("steps", steps)),
			member("parameters", raw("parameters", params)),
			member("created_at", now),
			member("updated_at", now),
		)
		dup, _ := decode(result)
		if err := l.validateSetBytes(dup.(map[string]any), nil); err != nil {
			return err
		}
		return l.saveSets(ctx, tx, userID, s, append(slices.Clone(s.sets), result))
	})
	if err != nil {
		return nil, storageError(err, "Failed to save command sets")
	}
	return result, nil
}

// DeleteSet is delete_command_set: a set a saved host starts with stays,
// and the refusal names at most 20 hosts. References of host contexts do
// not block; the host context checks them when it is saved.
func (l *Library) DeleteSet(ctx context.Context, userID int64, setID jsontext.Value) (string, error) {
	v, _ := decode(setID)
	id, isText := v.(string)
	err := l.DB.Write(ctx, func(tx *store.Tx) error {
		usages, err := l.setUsages(ctx, tx, userID, id, isText)
		if err != nil {
			return err
		}
		if len(usages) > 0 {
			names := make([]string, 0, MaxReferencedSetsShown)
			for _, u := range usages[:min(len(usages), MaxReferencedSetsShown)] {
				names = append(names, safeReferenceName(u.Name))
			}
			return inUse("Command set", len(usages), map[string]bool{"profile": true}, names, len(names))
		}
		s, err := readSnapshot(ctx, tx, userID)
		if err != nil {
			return err
		}
		var remaining []jsontext.Value
		for i, rec := range s.sets {
			if !isText || s.decoded[i]["id"] != id {
				remaining = append(remaining, rec)
			}
		}
		if len(remaining) == len(s.sets) {
			return errSetNotFound
		}
		return l.saveSets(ctx, tx, userID, s, remaining)
	})
	if err != nil {
		return "", storageError(err, "Failed to save command sets")
	}
	return id, nil
}
