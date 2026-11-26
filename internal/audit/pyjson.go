package audit

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// pyString appends s as a JSON string the way Python's json.dumps writes
// it with ensure_ascii=True: the short escapes \" \\ \n \r \t \b \f,
// \u00XX for the other control characters and \uXXXX (surrogate pairs
// above U+FFFF) for everything outside ASCII. Invalid UTF-8 becomes
// U+FFFD, as Python's errors="replace" decoding would produce.
func pyString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r < 0x20 || r > 0x7e:
			if r == utf8.RuneError {
				r = 0xfffd
			}
			if r > 0xffff {
				r -= 0x10000
				writeU(b, 0xd800+(r>>10))
				writeU(b, 0xdc00+(r&0x3ff))
				continue
			}
			writeU(b, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}

func writeU(b *strings.Builder, r rune) {
	hex := strconv.FormatInt(int64(r), 16)
	b.WriteString(`\u`)
	b.WriteString(strings.Repeat("0", 4-len(hex)))
	b.WriteString(hex)
}
