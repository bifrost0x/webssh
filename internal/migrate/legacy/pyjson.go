package legacy

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
)

// pythonJSONString encodes s as Python's json.dumps does with its default
// ensure_ascii=True. Secrets are bound to such text (AES-GCM additional
// data), so the bytes must match; encoding/json writes UTF-8 instead.
func pythonJSONString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			switch {
			case r < 0x20 || (r >= 0x7f && r <= 0xffff):
				fmt.Fprintf(&b, `\u%04x`, r)
			case r > 0xffff:
				hi, lo := utf16.EncodeRune(r)
				fmt.Fprintf(&b, `\u%04x\u%04x`, hi, lo)
			default:
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

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
