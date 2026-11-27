package automation

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// decodeOutput is bytes.decode('utf-8', errors='replace') of an
// incremental decoder: every maximal invalid subpart becomes one U+FFFD,
// as Python does. Unless final, an incomplete sequence at the end is
// held back and reported as pending.
func decodeOutput(b []byte, final bool) (string, bool) {
	var out strings.Builder
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		if r != utf8.RuneError || size > 1 {
			out.WriteRune(r)
			i += size
			continue
		}
		n, complete := invalidSubpart(b[i:])
		if !complete && !final {
			return out.String(), true
		}
		out.WriteRune(utf8.RuneError)
		i += n
	}
	return out.String(), false
}

// invalidSubpart is the length of the maximal subpart of an ill-formed
// sequence at the start of b (Unicode, "U+FFFD substitution of maximal
// subparts"), and whether it is complete: false when b ends inside a
// sequence that could still become valid.
func invalidSubpart(b []byte) (int, bool) {
	lead := b[0]
	var need int
	lo, hi := byte(0x80), byte(0xbf)
	switch {
	case lead >= 0xc2 && lead <= 0xdf:
		need = 1
	case lead == 0xe0:
		need, lo = 2, 0xa0
	case lead >= 0xe1 && lead <= 0xec, lead == 0xee, lead == 0xef:
		need = 2
	case lead == 0xed:
		need, hi = 2, 0x9f
	case lead == 0xf0:
		need, lo = 3, 0x90
	case lead >= 0xf1 && lead <= 0xf3:
		need = 3
	case lead == 0xf4:
		need, hi = 3, 0x8f
	default:
		return 1, true
	}
	n := 1
	for k := range need {
		if n >= len(b) {
			return n, false
		}
		c := b[n]
		if k == 0 && (c < lo || c > hi) || k > 0 && (c < 0x80 || c > 0xbf) {
			return n, true
		}
		n++
	}
	return n, true // unreachable for a sequence DecodeRune refused
}

// plainOutput is _plain_output: complete and interrupted terminal escape
// sequences are removed, line ends become LF, and control, format and
// surrogate characters other than LF and TAB are dropped.
func plainOutput(s string) string {
	r := []rune(s)
	r = stripStrings(r, func(r []rune, i int) int {
		if r[i] == 0x1b && i+1 < len(r) && r[i+1] == ']' {
			return 2
		}
		if r[i] == 0x9d {
			return 1
		}
		return 0
	}, true)
	r = stripStrings(r, func(r []rune, i int) int {
		if r[i] == 0x1b && i+1 < len(r) && strings.ContainsRune("P_X^", r[i+1]) {
			return 2
		}
		return 0
	}, false)
	r = stripCSI(r)
	r = stripEscapes(r)
	text := strings.ReplaceAll(string(r), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	return strings.Map(func(c rune) rune {
		if c == '\n' || c == '\t' || !(unicode.Is(unicode.Cc, c) || unicode.Is(unicode.Cf, c) || unicode.Is(unicode.Cs, c)) {
			return c
		}
		return -1
	}, text)
}

// atEnd is "$" of Python's re without MULTILINE: the end, or just before
// a final newline.
func atEnd(r []rune, j int) bool {
	return j == len(r) || (j == len(r)-1 && r[j] == '\n')
}

// stripStrings removes "intro .*? (BEL | ESC \ | $)" with DOTALL; bel
// allows BEL as terminator.
func stripStrings(r []rune, intro func([]rune, int) int, bel bool) []rune {
	out := make([]rune, 0, len(r))
	for i := 0; i < len(r); {
		n := intro(r, i)
		if n == 0 {
			out = append(out, r[i])
			i++
			continue
		}
		j := i + n
		for {
			if bel && j < len(r) && r[j] == 0x07 {
				j++
				break
			}
			if j+1 < len(r) && r[j] == 0x1b && r[j+1] == '\\' {
				j += 2
				break
			}
			if atEnd(r, j) {
				break
			}
			j++
		}
		i = j
	}
	return out
}

func between(c rune, lo, hi rune) bool { return c >= lo && c <= hi }

// stripCSI removes "(ESC [ | CSI) [0-?]* [ -/]* ([@-~] | $)".
func stripCSI(r []rune) []rune {
	out := make([]rune, 0, len(r))
	for i := 0; i < len(r); {
		n := 0
		if r[i] == 0x1b && i+1 < len(r) && r[i+1] == '[' {
			n = 2
		} else if r[i] == 0x9b {
			n = 1
		}
		if n > 0 {
			j := i + n
			for j < len(r) && between(r[j], 0x30, 0x3f) {
				j++
			}
			for j < len(r) && between(r[j], 0x20, 0x2f) {
				j++
			}
			switch {
			case j < len(r) && between(r[j], 0x40, 0x7e):
				i = j + 1
				continue
			case atEnd(r, j):
				i = j
				continue
			}
		}
		out = append(out, r[i])
		i++
	}
	return out
}

// stripEscapes removes "ESC ([ -/]* [@-~] | .*$)" with DOTALL: an escape
// that does not end in a final byte takes the rest of the text.
func stripEscapes(r []rune) []rune {
	out := make([]rune, 0, len(r))
	for i := 0; i < len(r); i++ {
		if r[i] != 0x1b {
			out = append(out, r[i])
			continue
		}
		j := i + 1
		for j < len(r) && between(r[j], 0x20, 0x2f) {
			j++
		}
		if j < len(r) && between(r[j], 0x40, 0x7e) {
			i = j
			continue
		}
		return out
	}
	return out
}

// redactOutput is _redact_output: every secret becomes [redacted], the
// longest first; an interrupted stream also loses a trailing prefix of a
// secret.
func redactOutput(value string, secrets []string, interrupted bool) string {
	set := map[string]bool{}
	var list []string
	for _, s := range secrets {
		if s != "" && !set[s] {
			set[s] = true
			list = append(list, s)
		}
	}
	sort.SliceStable(list, func(i, j int) bool { return utf8.RuneCountInString(list[i]) > utf8.RuneCountInString(list[j]) })
	for _, secret := range list {
		value = strings.ReplaceAll(value, secret, "[redacted]")
		if !interrupted {
			continue
		}
		sr := []rune(secret)
		vr := []rune(value)
		for size := min(len(sr)-1, len(vr)); size > 0; size-- {
			if strings.HasSuffix(value, string(sr[:size])) {
				value = string(vr[:len(vr)-size]) + "[redacted]"
				break
			}
		}
	}
	return value
}
