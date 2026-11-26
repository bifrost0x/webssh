package ldapproto

import (
	"errors"
	"fmt"
	"strings"
)

// Filter choice tags (RFC 4511 section 4.5.1).
const (
	filterAnd        = classContext | constructedBit
	filterOr         = classContext | constructedBit | 1
	filterNot        = classContext | constructedBit | 2
	filterEquality   = classContext | constructedBit | 3
	filterSubstrings = classContext | constructedBit | 4
	filterGreater    = classContext | constructedBit | 5
	filterLess       = classContext | constructedBit | 6
	filterPresent    = classContext | 7
	filterApprox     = classContext | constructedBit | 8
	filterExtensible = classContext | constructedBit | 9

	substringInitial = classContext
	substringAny     = classContext | 1
	substringFinal   = classContext | 2

	extensibleRule  = classContext | 1
	extensibleType  = classContext | 2
	extensibleValue = classContext | 3
	extensibleDN    = classContext | 4
)

// Bounds of a filter string. The configured template has at most 4096
// characters and the escaped user name at most 3072 bytes (256 characters,
// three bytes per escaped byte), so the length bound never refuses a
// filter the Python release sent. libldap has no depth bound; 512 levels
// are far beyond any sign-in template and keep the recursion small.
const (
	MaxFilterLength = 64 << 10
	maxFilterDepth  = 512
)

// ErrFilter reports a search filter string that libldap would refuse.
var ErrFilter = errors.New("ldap: invalid search filter")

func filterErr(what string) error { return fmt.Errorf("%w: %s", ErrFilter, what) }

// CompileFilter turns a filter string into its BER encoding. It accepts
// exactly the strings ldap_pvt_put_filter of libldap (OpenLDAP 2.6)
// accepts and produces the same octets: RFC 4515 filters, a bare item
// without parentheses ("uid=x"), white space after an opening parenthesis
// and between the members of a list, the RFC 1960 escapes \( \) \* \\,
// absolute true and false "(&)" and "(|)" (RFC 4526), and numeric
// attribute descriptions with leading zeros. The differential test against
// libldap (testdata/libldap_filters.json) pins this down.
func CompileFilter(s string) ([]byte, error) {
	if s == "" || len(s) > MaxFilterLength || strings.IndexByte(s, 0) >= 0 {
		return nil, filterErr("length or NUL")
	}
	out, err := putFilter(nil, s, 0)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		// libldap encodes nothing for a filter of one space and the server
		// then refuses the request; refuse it here.
		return nil, filterErr("empty filter")
	}
	return out, nil
}

// putFilter encodes s, which must consist of exactly one filter
// (ldap_pvt_put_filter).
func putFilter(dst []byte, s string, depth int) ([]byte, error) {
	if depth > maxFilterDepth {
		return nil, filterErr("nesting too deep")
	}
	i, parens := 0, 0
	for i < len(s) {
		var err error
		switch s[i] {
		case '(':
			i++
			parens++
			for i < len(s) && isLDAPSpace(s[i]) {
				i++
			}
			switch peekByte(s, i) {
			case '&':
				dst, i, err = putComplex(dst, s, i, filterAnd, depth)
			case '|':
				dst, i, err = putComplex(dst, s, i, filterOr, depth)
			case '!':
				dst, i, err = putComplex(dst, s, i, filterNot, depth)
			case '(':
				err = filterErr("nested parenthesis without operator")
			default:
				end := findRightParen(s, i)
				if end < 0 {
					err = filterErr("unbalanced parenthesis")
					break
				}
				dst, err = putSimple(dst, s[i:end])
				i = end + 1
			}
			parens--
		case ')':
			// libldap never recovers from a closing parenthesis it did not
			// open.
			err = filterErr("unexpected closing parenthesis")
		case ' ':
			i++
		default:
			dst, err = putSimple(dst, s[i:])
			i = len(s)
		}
		if err != nil {
			return nil, err
		}
		if parens == 0 {
			break
		}
	}
	if parens != 0 || i < len(s) {
		return nil, filterErr("trailing data")
	}
	return dst, nil
}

func peekByte(s string, i int) byte {
	if i < len(s) {
		return s[i]
	}
	return 0
}

// isLDAPSpace is LDAP_SPACE of libldap.
func isLDAPSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' }

// findRightParen returns the index of the parenthesis that closes one
// already open before from, skipping escaped characters, or -1
// (find_right_paren).
func findRightParen(s string, from int) int {
	balance, escape := 1, false
	for i := from; i < len(s); i++ {
		if !escape {
			switch s[i] {
			case '(':
				balance++
			case ')':
				balance--
			}
		}
		if balance == 0 {
			return i
		}
		escape = s[i] == '\\' && !escape
	}
	return -1
}

// putComplex encodes "&…)", "|…)" or "!…)" with s[i] on the operator and
// returns the index after the closing parenthesis (put_complex_filter).
func putComplex(dst []byte, s string, i int, tag byte, depth int) ([]byte, int, error) {
	start := i + 1
	end := findRightParen(s, start)
	if end < 0 {
		return nil, 0, filterErr("unbalanced parenthesis")
	}
	body, err := putFilterList(s[start:end], tag, depth)
	if err != nil {
		return nil, 0, err
	}
	return appendTLV(dst, tag, body), end + 1, nil
}

// putFilterList encodes the members of a list; "!" takes exactly one
// (put_filter_list).
func putFilterList(s string, tag byte, depth int) ([]byte, error) {
	var body []byte
	members, i := 0, 0
	for i < len(s) {
		for i < len(s) && isLDAPSpace(s[i]) {
			i++
		}
		if i >= len(s) {
			break
		}
		end := findRightParen(s, i+1)
		if end < 0 {
			return nil, filterErr("unbalanced parenthesis in list")
		}
		var err error
		if body, err = putFilter(body, s[i:end+1], depth+1); err != nil {
			return nil, err
		}
		members++
		i = end + 1
		if tag == filterNot {
			break
		}
	}
	if tag == filterNot && (members == 0 || i < len(s)) {
		return nil, filterErr("negation needs exactly one filter")
	}
	return body, nil
}

// putSimple encodes one item "attr op value" (put_simple_filter).
func putSimple(dst []byte, item string) ([]byte, error) {
	eq := strings.IndexByte(item, '=')
	if eq <= 0 {
		return nil, filterErr("item without attribute or '='")
	}
	attr, value := item[:eq], item[eq+1:]
	var tag byte
	switch attr[len(attr)-1] {
	case '<':
		tag, attr = filterLess, attr[:len(attr)-1]
	case '>':
		tag, attr = filterGreater, attr[:len(attr)-1]
	case '~':
		tag, attr = filterApprox, attr[:len(attr)-1]
	case ':':
		return putExtensible(dst, attr[:len(attr)-1], value)
	default:
		if !isDescription(attr) {
			return nil, filterErr("invalid attribute description")
		}
		star := findWildcard(value)
		switch {
		case star < 0:
			return nil, filterErr("invalid value")
		case star == len(value):
			tag = filterEquality
		case value == "*":
			return appendOctetString(dst, filterPresent, attr), nil
		default:
			return putSubstrings(dst, attr, value, star)
		}
	}
	if !isDescription(attr) {
		return nil, filterErr("invalid attribute description")
	}
	v, ok := unescapeValue(value)
	if !ok {
		return nil, filterErr("invalid value")
	}
	var body []byte
	body = appendOctetString(body, tagOctetString, attr)
	body = appendOctetString(body, tagOctetString, v)
	return appendTLV(dst, tag, body), nil
}

// putSubstrings encodes a substring item; star is the index of the first
// wildcard in value (put_substring_filter).
func putSubstrings(dst []byte, attr, value string, star int) ([]byte, error) {
	var subs []byte
	seen := 0
	for rest := value; rest != ""; {
		if seen > 0 {
			star = findWildcard(rest)
		}
		if star < 0 {
			return nil, filterErr("invalid substring")
		}
		var tag byte
		piece := rest
		if star == len(rest) {
			tag, rest = substringFinal, ""
		} else {
			piece, rest = rest[:star], rest[star+1:]
			tag = substringAny
			if seen == 0 {
				tag = substringInitial
			}
			seen++
		}
		if piece == "" && tag != substringAny {
			continue
		}
		v, ok := unescapeValue(piece)
		if !ok || v == "" {
			return nil, filterErr("empty or invalid substring")
		}
		subs = appendOctetString(subs, tag, v)
	}
	var body []byte
	body = appendOctetString(body, tagOctetString, attr)
	body = appendTLV(body, tagSequence, subs)
	return appendTLV(dst, filterSubstrings, body), nil
}

// putExtensible encodes "type[:dn][:rule]:=value" or "[:dn]:rule:=value";
// head is everything before ":=".
func putExtensible(dst []byte, head, value string) ([]byte, error) {
	typ, rule, hasRule, dnAttrs := head, "", false, false
	if t, dn, ok := strings.Cut(head, ":"); ok {
		typ = t
		if marker, r, two := strings.Cut(dn, ":"); two {
			if !asciiEqualFold(marker, "dn") {
				return nil, filterErr("invalid extensible match")
			}
			rule, hasRule, dnAttrs = r, true, true
		} else if asciiEqualFold(dn, "dn") {
			if !isDescription(typ) {
				return nil, filterErr("dn attributes need a type")
			}
			dnAttrs, hasRule = true, true
		} else {
			rule, hasRule = dn, true
		}
	}
	switch {
	case typ == "" && (!hasRule || rule == ""):
		return nil, filterErr("extensible match needs a type or a rule")
	case typ != "" && !isDescription(typ):
		return nil, filterErr("invalid attribute description")
	case rule != "" && !isOID(rule):
		return nil, filterErr("invalid matching rule")
	}
	v, ok := unescapeValue(value)
	if !ok {
		return nil, filterErr("invalid value")
	}
	var body []byte
	if rule != "" {
		body = appendOctetString(body, extensibleRule, rule)
	}
	if typ != "" {
		body = appendOctetString(body, extensibleType, typ)
	}
	body = appendOctetString(body, extensibleValue, v)
	if dnAttrs {
		body = appendBool(body, extensibleDN, true)
	}
	return appendTLV(dst, filterExtensible, body), nil
}

func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		if lowerASCII(a[i]) != lowerASCII(b[i]) {
			return false
		}
	}
	return true
}

func lowerASCII(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}
