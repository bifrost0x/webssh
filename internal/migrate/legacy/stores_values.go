package legacy

import (
	json "encoding/json/v2"
	"fmt"

	"github.com/bifrost0x/webssh/internal/pyjson"
)

// withValues fills Object, Items and Entries of a document that
// decodeStore returned. The migration steps work on Raw; the generic
// values cost several times the size of the file, so only the public
// readers of the package decode them.
func (d Document) withValues(spec storeSpec) (Document, error) {
	var top any
	if err := json.Unmarshal(d.Raw, &top, numbersAsText); err != nil {
		return Document{}, fmt.Errorf("invalid JSON: %w", err)
	}
	if spec.topList {
		switch v := top.(type) {
		case []any:
			d.Items = v
		case map[string]any:
			d.Object, d.Items = v, v["commands"].([]any)
		}
		return d, nil
	}
	d.Object, _ = top.(map[string]any)
	if spec.listKey != "" {
		switch v := d.Object[spec.listKey].(type) {
		case []any:
			d.Items = v
		case map[string]any:
			d.Entries = v
		}
	}
	return d, nil
}

// records counts the records under the store's list key (or of the bare
// array) without decoding them: the items of a list, the members of a
// map.
func (d Document) records(listKey string) int {
	list := d.Raw
	if listKey != "" {
		v, ok := pyjson.Get(d.Raw, listKey)
		if !ok {
			return 0
		}
		list = v
	}
	return pyjson.Len(list)
}
