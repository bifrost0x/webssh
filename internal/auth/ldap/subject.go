package ldap

import (
	"bytes"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ErrInvalidSubject reports a unique-ID value that cannot be an identity.
var ErrInvalidSubject = errors.New("ldap: identity attribute is invalid")

const (
	maxSubjectRunes = 512
	// pyMaxStrDigits is CPython's default sys.int_info.default_max_str_digits.
	pyMaxStrDigits = 4300
)

// CanonicalSubject maps a raw unique-ID attribute value to the subject
// string that the Python release stored for the LDAP identity binding. The stored
// bindings are a compatibility contract, so this reproduces the Python chain
// exactly: Bonsai's value conversion (bonsai 1.5.5, src/_bonsai/utils.c,
// berval2PyObject with keepbytes=0) followed by _canonical_subject in
// app/ldap_service.py.
//
//  1. The value as C string (up to the first NUL) equal to "TRUE" or
//     "FALSE" becomes Python's "True" or "False".
//  2. The C string accepted by PyLong_FromString(s, NULL, 0) becomes the
//     decimal form of that integer.
//  3. Otherwise valid UTF-8 is kept as text, anything else becomes
//     "b64:" plus unpadded URL-safe base64 of the raw bytes.
//  4. Python str.strip(); empty, longer than 512 code points or containing
//     NUL is rejected.
func CanonicalSubject(raw []byte) (string, error) {
	s, _, err := canonicalSubject(raw)
	return s, err
}

// Subjects returns the subject of a new identity binding for raw and,
// when it differs, the subject the Python release stored for it. The
// Python form of a value with a NUL byte is read from the C string before
// the NUL, so different values (binary objectGUIDs starting with a digit
// and NUL) shared it; the subject of a new binding is then "b64:" plus
// the whole value. legacy is "" when both are the same.
func Subjects(raw []byte) (subject, legacy string, err error) {
	s, truncated, err := canonicalSubject(raw)
	if err != nil || !truncated {
		return s, "", err
	}
	return "b64:" + base64.RawURLEncoding.EncodeToString(raw), s, nil
}

// canonicalSubject is CanonicalSubject; truncated reports that the
// subject was read from the C string of a value with a NUL byte.
func canonicalSubject(raw []byte) (string, bool, error) {
	cstr := raw
	if before, _, ok := bytes.Cut(raw, []byte{0}); ok {
		cstr = before
	}
	var s string
	text, truncated := true, len(cstr) < len(raw)
	switch {
	case string(cstr) == "TRUE":
		s = "True"
	case string(cstr) == "FALSE":
		s = "False"
	default:
		if n, ok := pyLongBase0(string(cstr)); ok {
			s = n.String()
			break
		}
		// The whole value is used: as text, or as "b64:" plus the base64
		// form, which Python does not strip.
		truncated = false
		if utf8.Valid(raw) {
			s = string(raw)
		} else {
			s = "b64:" + base64.RawURLEncoding.EncodeToString(raw)
			text = false
		}
	}
	if text {
		s = strings.TrimFunc(s, pyIsSpace)
	}
	if s == "" || utf8.RuneCountInString(s) > maxSubjectRunes || strings.ContainsRune(s, 0) {
		return "", false, ErrInvalidSubject
	}
	return s, truncated, nil
}

// pyIsSpace matches Python's str.isspace: Unicode White_Space plus the
// separators U+001C..U+001F, which Python counts and Go does not.
func pyIsSpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
}

// pyCSpace matches Py_ISSPACE, used by PyLong_FromString on bytes.
func pyCSpace(c byte) bool {
	return c == ' ' || (c >= '\t' && c <= '\r')
}

// pyLongBase0 implements the grammar of PyLong_FromString with base 0:
// optional surrounding ASCII whitespace, a sign, a 0x/0o/0b prefix or a
// decimal without leading zeros, and single underscores between digits.
func pyLongBase0(s string) (*big.Int, bool) {
	i, j := 0, len(s)
	for i < j && pyCSpace(s[i]) {
		i++
	}
	for j > i && pyCSpace(s[j-1]) {
		j--
	}
	s = s[i:j]
	neg := false
	if s != "" && (s[0] == '+' || s[0] == '-') {
		neg = s[0] == '-'
		s = s[1:]
	}
	base := 10
	if len(s) >= 2 && s[0] == '0' {
		switch s[1] | 0x20 {
		case 'x':
			base = 16
		case 'o':
			base = 8
		case 'b':
			base = 2
		}
		if base != 10 {
			s = s[2:]
			// An underscore may directly follow the prefix ("0x_1f").
			s = strings.TrimPrefix(s, "_")
		}
	}
	digits, ok := stripUnderscores(s, base)
	if !ok {
		return nil, false
	}
	if base == 10 && len(digits) > pyMaxStrDigits {
		return nil, false
	}
	if base == 10 && len(digits) > 1 && digits[0] == '0' && strings.Trim(digits, "0") != "" {
		return nil, false
	}
	n, ok := new(big.Int).SetString(digits, base)
	if !ok {
		return nil, false
	}
	if neg {
		n.Neg(n)
	}
	return n, true
}

// stripUnderscores removes single underscores that separate digits and
// checks every character is a digit of base.
func stripUnderscores(s string, base int) (string, bool) {
	if s == "" || s[0] == '_' || s[len(s)-1] == '_' {
		return "", false
	}
	var b strings.Builder
	prevUnderscore := false
	for k := 0; k < len(s); k++ {
		c := s[k]
		if c == '_' {
			if prevUnderscore {
				return "", false
			}
			prevUnderscore = true
			continue
		}
		prevUnderscore = false
		if digitValue(c) >= base {
			return "", false
		}
		b.WriteByte(c)
	}
	return b.String(), true
}

func digitValue(c byte) int {
	switch {
	case '0' <= c && c <= '9':
		return int(c - '0')
	case 'a' <= c && c <= 'z':
		return int(c-'a') + 10
	case 'A' <= c && c <= 'Z':
		return int(c-'A') + 10
	}
	return 99
}
