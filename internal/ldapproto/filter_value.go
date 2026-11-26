package ldapproto

import "strings"

func isAlpha(c byte) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }

func isDigit(c byte) bool { return '0' <= c && c <= '9' }

func isLDH(c byte) bool { return isAlpha(c) || isDigit(c) || c == '-' }

func hexValue(c byte) (byte, bool) {
	switch {
	case isDigit(c):
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// isDescription is ldap_is_desc: a descriptor (letter, then letters,
// digits and '-') or a numeric OID (digits and single dots, leading zeros
// allowed, no trailing dot), each followed by options ";opt" whose
// characters are letters, digits and '-'.
func isDescription(s string) bool {
	typ, options, hasOptions := strings.Cut(s, ";")
	if !isOID(typ) {
		return false
	}
	for hasOptions {
		var opt string
		opt, options, hasOptions = strings.Cut(options, ";")
		if opt == "" {
			return false
		}
		for i := range len(opt) {
			if !isLDH(opt[i]) {
				return false
			}
		}
	}
	return true
}

// isOID is ldap_is_oid: a descriptor or a numeric OID as isDescription
// accepts them, without options.
func isOID(s string) bool {
	switch {
	case s == "":
		return false
	case isAlpha(s[0]):
		for i := 1; i < len(s); i++ {
			if !isLDH(s[i]) {
				return false
			}
		}
		return true
	case isDigit(s[0]):
		dot := false
		for i := 1; i < len(s); i++ {
			switch {
			case isDigit(s[i]):
				dot = false
			case s[i] == '.' && !dot:
				dot = true
			default:
				return false
			}
		}
		return !dot
	}
	return false
}

// findWildcard returns the index of the first unescaped '*' in v, len(v)
// when there is none, or -1 for an unescaped parenthesis or an invalid
// escape (ldap_pvt_find_wildcard).
func findWildcard(v string) int {
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '*':
			return i
		case '(', ')':
			return -1
		case '\\':
			if i+1 >= len(v) {
				return -1
			}
			_, hi := hexValue(v[i+1])
			lo := false
			if i+2 < len(v) {
				_, lo = hexValue(v[i+2])
			}
			switch {
			case hi && lo:
				i += 2
			case strings.IndexByte(`*()\`, v[i+1]) >= 0:
				i++
			default:
				return -1
			}
		}
	}
	return len(v)
}

// unescapeValue decodes an assertion value with the LDAPv3 escapes \XX and
// the LDAPv2 escapes \( \) \* \\; an unescaped parenthesis or asterisk is
// refused (ldap_pvt_filter_value_unescape). The result may hold NUL.
func unescapeValue(v string) (string, bool) {
	if !strings.ContainsAny(v, `()*\`) {
		return v, true
	}
	var b strings.Builder
	b.Grow(len(v))
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch c {
		case '(', ')', '*':
			return "", false
		case '\\':
			i++
			if i >= len(v) {
				return "", false
			}
			if hi, ok := hexValue(v[i]); ok {
				if i+1 >= len(v) {
					return "", false
				}
				lo, ok := hexValue(v[i+1])
				if !ok {
					return "", false
				}
				b.WriteByte(hi<<4 | lo)
				i++
				continue
			}
			if strings.IndexByte(`()*\`, v[i]) < 0 {
				return "", false
			}
			b.WriteByte(v[i])
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), true
}

// EscapeFilterValue escapes an assertion value like escape_filter_value of
// the Python release: RFC 4515 section 3 (NUL, '(', ')', '*', '\') and
// every byte >= 0x80, as lower-case \XX. The produced value is plain
// ASCII and decodes to exactly the input bytes.
func EscapeFilterValue(v string) string {
	const hexDigits = "0123456789abcdef"
	var b strings.Builder
	b.Grow(len(v))
	for i := range len(v) {
		c := v[i]
		if c == 0x00 || c == '(' || c == ')' || c == '*' || c == '\\' || c >= 0x80 {
			b.WriteByte('\\')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0x0f])
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}
