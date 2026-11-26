package legacy

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/bifrost0x/webssh/internal/pyjson"
)

// pythonJSONString encodes s as Python's json.dumps does with its default
// ensure_ascii=True (pyjson.Quote).
func pythonJSONString(s string) string { return pyjson.Quote(s) }

// pythonCompactJSON encodes a flat list of strings and integers as
// json.dumps(values, separators=(",", ":")).
func pythonCompactJSON(values ...any) (string, error) {
	parts := make([]string, len(values))
	for i, v := range values {
		switch v := v.(type) {
		case string:
			parts[i] = pythonJSONString(v)
		case int64:
			parts[i] = strconv.FormatInt(v, 10)
		default:
			return "", fmt.Errorf("legacy: cannot encode %T", v)
		}
	}
	return "[" + strings.Join(parts, ",") + "]", nil
}
