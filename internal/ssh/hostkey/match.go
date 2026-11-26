package hostkey

import (
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- hashed known_hosts names are HMAC-SHA1 by definition (OpenSSH).
	"encoding/base64"
	"strings"
	"unicode"
	"unicode/utf8"
)

const hashedPrefix = "|1|"

// validPattern accepts what the Python store accepted: a non-empty pattern,
// optionally negated, and hashed names only with a 20-byte salt and digest.
func validPattern(pattern string) bool {
	pattern = strings.TrimPrefix(pattern, "!")
	if pattern == "" {
		return false
	}
	if !strings.HasPrefix(pattern, "|") {
		return true
	}
	_, _, ok := splitHashed(pattern)
	return ok
}

func splitHashed(pattern string) (salt, digest []byte, ok bool) {
	fields := strings.Split(pattern, "|")
	if len(fields) != 4 || fields[0] != "" || fields[1] != "1" {
		return nil, nil, false
	}
	salt, err := base64.StdEncoding.Strict().DecodeString(fields[2])
	if err != nil || len(salt) != sha1.Size {
		return nil, nil, false
	}
	digest, err = base64.StdEncoding.Strict().DecodeString(fields[3])
	if err != nil || len(digest) != sha1.Size {
		return nil, nil, false
	}
	return salt, digest, true
}

// patternMatches matches one non-negated pattern against the lookup name.
// Hashed names are compared for the name as given and in lower case;
// plain patterns are case-insensitive globs over the whole name.
func patternMatches(hostname, pattern string) bool {
	if strings.HasPrefix(pattern, hashedPrefix) {
		salt, digest, ok := splitHashed(pattern)
		if !ok {
			return false
		}
		for _, candidate := range []string{hostname, strings.ToLower(hostname)} {
			mac := hmac.New(sha1.New, salt)
			mac.Write([]byte(candidate))
			if hmac.Equal(mac.Sum(nil), digest) {
				return true
			}
		}
		return false
	}
	return globFold(pattern, hostname)
}

// entryMatches applies the OpenSSH list semantics Python used: any matching
// negated pattern excludes the entry, otherwise one positive match is needed.
func entryMatches(hostname string, entry Entry) bool {
	matched := false
	for _, raw := range entry.Patterns {
		negated := strings.HasPrefix(raw, "!")
		pattern := strings.TrimPrefix(raw, "!")
		if !patternMatches(hostname, pattern) {
			continue
		}
		if negated {
			return false
		}
		matched = true
	}
	return matched
}

// globFold matches '*' (any run) and '?' (one character) over code points,
// comparing other characters with Unicode simple case folding, like Python's
// re.fullmatch with re.IGNORECASE.
func globFold(pattern, name string) bool {
	p, n := []rune(pattern), []rune(name)
	pi, ni := 0, 0
	star, mark := -1, 0
	for ni < len(n) {
		switch {
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, ni
			pi++
		case pi < len(p) && (p[pi] == '?' || foldEqual(p[pi], n[ni])):
			pi++
			ni++
		case star >= 0:
			pi = star + 1
			mark++
			ni = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

func foldEqual(a, b rune) bool {
	if a == b {
		return true
	}
	if a < utf8.RuneSelf && b < utf8.RuneSelf {
		return unicode.ToLower(a) == unicode.ToLower(b)
	}
	for f := unicode.SimpleFold(a); f != a; f = unicode.SimpleFold(f) {
		if f == b {
			return true
		}
	}
	return false
}
