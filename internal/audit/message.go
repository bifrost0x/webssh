package audit

import (
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// Field is one key=value detail of an event. Values are strings, integers,
// booleans or nil; nil fields are left out, like None in the Python
// release.
type Field struct {
	Key   string
	Value any
}

// F returns a field.
func F(key string, value any) Field { return Field{Key: key, Value: value} }

const maxValueRunes = 512

// sanitize is _sanitize_log_value: line breaks, NUL and the field
// separator are escaped, so a value cannot forge a line or a field, and
// the result is cut to 512 code points.
func sanitize(s string) string {
	r := strings.NewReplacer("\n", `\n`, "\r", `\r`, "\x00", `\x00`, "|", `\|`)
	s = r.Replace(s)
	if n := 0; len(s) > maxValueRunes {
		for i := range s {
			if n == maxValueRunes {
				return s[:i]
			}
			n++
		}
	}
	return s
}

// pyStr renders a value like Python's str().
func pyStr(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case string:
		return x
	case bool:
		if x {
			return "True"
		}
		return "False"
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	default:
		// Only the types above are part of the format; anything else is a
		// programming error and must not leak its representation.
		return "[UNSUPPORTED]"
	}
}

var sensitiveKeys = []string{
	"assertion", "authorization", "cookie", "credential", "password",
	"passphrase", "private_key", "recovery_code", "secret", "token", "totp_code",
}

var sensitiveParts = []string{
	"assertion", "assertions", "authorization", "cookie", "cookies",
	"credential", "credentials", "passphrase", "passphrases", "password",
	"passwords", "secret", "secrets", "token", "tokens",
}

// sensitiveKey is _audit_detail_key_is_sensitive.
func sensitiveKey(key string) bool {
	var b strings.Builder
	for _, r := range key {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteString(strings.ToLower(string(r)))
		} else {
			b.WriteByte('_')
		}
	}
	norm := strings.Trim(b.String(), "_")
	if slices.Contains(sensitiveKeys, norm) {
		return true
	}
	for _, k := range sensitiveKeys {
		if strings.HasSuffix(norm, "_"+k) {
			return true
		}
	}
	for part := range strings.SplitSeq(norm, "_") {
		if slices.Contains(sensitiveParts, part) {
			return true
		}
	}
	return false
}

// eventName is the event normalisation of log_security_event.
func eventName(event string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(event) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	name := []rune(strings.Trim(b.String(), "_"))
	return string(name[:min(len(name), 96)])
}

// eventMessage builds the message of log_security_event. Keys are
// sanitised once, values twice (the Python release sanitises the detail
// dictionary and then every value again), and the fields are sorted by
// key. At most 64 fields are kept, in the order given.
func eventMessage(event string, fields []Field) string {
	type kv struct{ k, v string }
	var details []kv
	seen := map[string]int{}
	for _, f := range fields[:min(len(fields), 64)] {
		key := sanitize(f.Key)
		var value string
		var isNil bool
		switch {
		case sensitiveKey(f.Key):
			value = "[REDACTED]"
		case f.Value == nil:
			isNil = true
		case isScalar(f.Value):
			value = pyStr(f.Value)
		default:
			value = sanitize(pyStr(f.Value))
		}
		if i, ok := seen[key]; ok {
			// A later duplicate key replaces the earlier value (dict).
			details[i] = kv{key, value}
			if isNil {
				details[i].v = "\x00nil"
			}
			continue
		}
		if isNil {
			value = "\x00nil"
		}
		seen[key] = len(details)
		details = append(details, kv{key, value})
	}
	slices.SortStableFunc(details, func(a, b kv) int { return strings.Compare(a.k, b.k) })
	var b strings.Builder
	b.WriteString(eventName(event))
	for _, d := range details {
		if d.v == "\x00nil" {
			continue
		}
		b.WriteString(" | ")
		b.WriteString(d.k)
		b.WriteByte('=')
		b.WriteString(sanitize(d.v))
	}
	return b.String()
}

// isScalar reports the types the Python release keeps unchanged in the
// detail dictionary (bool, int); strings are sanitised there.
func isScalar(v any) bool {
	switch v.(type) {
	case bool, int, int64:
		return true
	}
	return false
}
