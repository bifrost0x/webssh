package commands

import (
	_ "embed"
	"encoding/json/jsontext"
	"fmt"
	"sync"

	"github.com/bifrost0x/webssh/internal/pyjson"
)

// systemCommandsJSON is app/resources/commands/system_commands.json, the
// built-in templates (ids sys-NNN). Their names and descriptions are
// translated by the page (static/i18n/commands). A test keeps the copy
// equal to the Python resource while both exist.
//
//go:embed system_commands.json
var systemCommandsJSON []byte

var systemCommands = sync.OnceValues(func() ([]jsontext.Value, error) {
	doc, _, err := pyjson.Load(systemCommandsJSON)
	if err != nil {
		return nil, fmt.Errorf("commands: built-in templates: %w", err)
	}
	items, ok := pyjson.Items(doc)
	if !ok {
		return nil, fmt.Errorf("commands: built-in templates are not a list")
	}
	return items, nil
})

// SystemCommands returns the built-in templates as the library lists
// them: each with isSystem true and userId null.
func SystemCommands() ([]jsontext.Value, error) {
	items, err := systemCommands()
	if err != nil {
		return nil, err
	}
	out := make([]jsontext.Value, len(items))
	for i, it := range items {
		members, ok := pyjson.Members(it)
		if !ok {
			return nil, fmt.Errorf("commands: built-in template %d is not an object", i)
		}
		members = pyjson.Set(members, "isSystem", jsontext.Value("true"))
		members = pyjson.Set(members, "userId", jsontext.Value("null"))
		out[i] = pyjson.Object(members)
	}
	return out, nil
}
