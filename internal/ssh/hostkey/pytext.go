package hostkey

import (
	"strings"
	"unicode"
)

// The stored known_hosts files were written and parsed by Python. These
// helpers reproduce the exact text rules Python applied, so a line that
// was valid before the update is valid now and nothing else is.

// pySplitByteLines mirrors bytes.splitlines(): only \n, \r and \r\n.
func pySplitByteLines(raw []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\n' && raw[i] != '\r' {
			continue
		}
		lines = append(lines, raw[start:i])
		if raw[i] == '\r' && i+1 < len(raw) && raw[i+1] == '\n' {
			i++
		}
		start = i + 1
	}
	if start < len(raw) {
		lines = append(lines, raw[start:])
	}
	return lines
}

// pyIsSpace mirrors str.isspace() for one code point.
func pyIsSpace(r rune) bool {
	switch r {
	case 0x1c, 0x1d, 0x1e, 0x1f:
		return true
	}
	return unicode.IsSpace(r) || unicode.Is(unicode.Zs, r)
}

// pyStrip mirrors str.strip() without arguments.
func pyStrip(s string) string {
	return strings.TrimFunc(s, pyIsSpace)
}

// pyFields mirrors re.split(r"[ \t]+", s) on an already stripped string.
func pyFields(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == '\t' })
}
