package commands

import (
	"encoding/json/jsontext"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/pyjson"
)

// The rules of app/command_set_manager.py for one set, over decoded
// values (dict and list as Python sees them).

// normalizeSteps is _normalize_steps: the steps as they are stored and
// the text each one resolves to, or the message of a refusal.
func normalizeSteps(stepsValue any, idx commandIndex) ([]jsontext.Value, []string, string) {
	steps, ok := stepsValue.([]any)
	if !ok || len(steps) == 0 {
		return nil, nil, "Command set must contain at least one step"
	}
	var stored []jsontext.Value
	var parts []string
	for i, raw := range steps {
		pos := i + 1
		step, ok := raw.(map[string]any)
		if !ok {
			return nil, nil, fmt.Sprintf("Command set step %d has an invalid type", pos)
		}
		switch step["type"] {
		case string(StepInline):
			command, ok := step["command"].(string)
			if !ok {
				return nil, nil, fmt.Sprintf("Command set step %d is empty", pos)
			}
			normalized, msg := normalizeStartup(command)
			if msg != "" {
				return nil, nil, msg
			}
			if pyStrip(normalized) == "" {
				return nil, nil, fmt.Sprintf("Command set step %d is empty", pos)
			}
			stored = append(stored, object(member("type", rawString("inline")), member("command", rawString(normalized))))
			parts = append(parts, normalized)
		case string(StepLibrary):
			id, ok := step["command_id"].(string)
			command, found := idx[id]
			if !ok || !found {
				return nil, nil, fmt.Sprintf("Command set step %d references a missing command", pos)
			}
			members := []pyjson.Member{member("type", rawString("library")), member("command_id", rawString(id))}
			var params any
			override, hasOverride := step["parameters_override"]
			if hasOverride {
				if override != nil {
					text, isText := override.(string)
					if !isText {
						return nil, nil, "Command parameters must be a string"
					}
					if msg := validateCommandParameters(text); msg != "" {
						return nil, nil, msg
					}
				}
				members = append(members, member("parameters_override", rawValue(override)))
				params = override
			}
			if params == nil {
				params, ok = command["parameters"]
				if !ok {
					params = ""
				}
			}
			text, isText := params.(string)
			if !isText {
				return nil, nil, "Command parameters must be a string"
			}
			if msg := validateCommandParameters(text); msg != "" {
				return nil, nil, msg
			}
			line := command["command"].(string)
			if text != "" {
				line += " " + text
			}
			stored = append(stored, pyjson.Object(members))
			parts = append(parts, line)
		default:
			return nil, nil, fmt.Sprintf("Command set step %d has an invalid type", pos)
		}
	}
	if _, msg := normalizeStartup(strings.Join(parts, "\n")); msg != "" {
		return nil, nil, msg
	}
	return stored, parts, ""
}

// parameterSet reads the declarations and argv steps of a set for
// validateParameterSet.
func parameterSet(paramsValue, stepsValue any) ([]rawParam, bool, []rawArgvStep, bool) {
	paramsList, isParams := paramsValue.([]any)
	params := make([]rawParam, len(paramsList))
	for i, p := range paramsList {
		m, ok := p.(map[string]any)
		params[i] = rawParam{members: m, isObj: ok}
	}
	stepsList, isSteps := stepsValue.([]any)
	steps := make([]rawArgvStep, len(stepsList))
	for i, s := range stepsList {
		m, ok := s.(map[string]any)
		argv, isArgv := m["argv"].([]any)
		steps[i] = rawArgvStep{isObj: ok, typ: m["type"], argv: argv, argvSet: isArgv}
	}
	return params, isParams, steps, isSteps
}

// checkParameterSet is validate_parameter_set of a decoded set.
func checkParameterSet(set map[string]any) string {
	params, isParams, steps, isSteps := parameterSet(set["parameters"], set["steps"])
	return validateParameterSet(params, isParams, steps, isSteps)
}

// argvSteps returns the argv lists of a set that passed
// checkParameterSet, and its declared names.
func argvSteps(set map[string]any) ([][]string, []string) {
	var steps [][]string
	for _, s := range set["steps"].([]any) {
		raw := s.(map[string]any)["argv"].([]any)
		argv := make([]string, len(raw))
		for i, a := range raw {
			argv[i] = a.(string)
		}
		steps = append(steps, argv)
	}
	var names []string
	for _, p := range set["parameters"].([]any) {
		names = append(names, p.(map[string]any)["name"].(string))
	}
	return steps, names
}

// resolveLoaded is _resolve_loaded_command_set: the startup text of a
// stored set without parameters, with sudo when the set asks for it.
func resolveLoaded(set map[string]any, idx commandIndex, forceSudo bool) (string, string) {
	if truthy(set["parameters"]) {
		return "", msgInteractive
	}
	_, parts, msg := normalizeSteps(set["steps"], idx)
	if msg != "" {
		if strings.Contains(msg, "step ") {
			name, _ := set["name"].(string)
			return "", fmt.Sprintf("Command set '%s' %s", name, strings.ToLower(strings.TrimPrefix(msg, "Command set ")))
		}
		return "", msg
	}
	sudo := forceSudo || set["use_sudo"] == true
	resolved, msg := normalizeStartup(chainSteps(parts, sudo))
	return resolved, msg
}

// validateSetBytes is validate_command_set: the byte limits of one set
// against the stored set it replaces.
func (l *Library) validateSetBytes(set, legacy map[string]any) error {
	for _, f := range []struct {
		name  string
		limit int
		label string
	}{
		{"id", maxCommandIDBytes, "command set id"},
		{"name", MaxCommandNameBytes, "command set name"},
		{"description", maxDescriptionBytes, "command set description"},
	} {
		v, ok := set[f.name]
		if !ok {
			v = ""
		}
		if err := boundedText(v, f.limit, f.label, legacy[f.name]); err != nil {
			return err
		}
	}
	steps, ok := set["steps"].([]any)
	if !ok {
		return quota("command set steps must be a list")
	}
	old, _ := legacy["steps"].([]any)
	if len(steps) > l.Limits.withDefaults().MaxSetSteps && len(steps) > len(old) {
		return quota("too many command set steps")
	}
	for i, s := range steps {
		previous := map[string]any{}
		if i < len(old) {
			if p, ok := old[i].(map[string]any); ok {
				previous = p
			}
		}
		step, ok := s.(map[string]any)
		if !ok {
			return quota("command set step is invalid")
		}
		switch step["type"] {
		case string(StepInline):
			if err := boundedText(textOr(step, "command"), MaxCommandBytes, "inline command", previous["command"]); err != nil {
				return err
			}
		case string(StepLibrary):
			if err := boundedText(textOr(step, "command_id"), maxCommandIDBytes, "command reference", previous["command_id"]); err != nil {
				return err
			}
			if override, ok := step["parameters_override"]; ok && override != nil {
				if err := boundedText(override, MaxCommandBytes, "command parameter override", previous["parameters_override"]); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// textOr is step.get(name, "").
func textOr(m map[string]any, name string) any {
	if v, ok := m[name]; ok {
		return v
	}
	return ""
}

// runeLen is Python's len of a string.
func runeLen(s string) int { return utf8.RuneCountInString(s) }
