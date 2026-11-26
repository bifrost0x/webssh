package hostkey

import (
	"bytes"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/crypto/ssh"
)

// Scope says which store a key came from.
type Scope string

const (
	ScopeUser   Scope = "user"
	ScopeGlobal Scope = "global"
)

// TrustedKey is the effective trusted key of one key type for a host.
type TrustedKey struct {
	Type  string
	Key   ssh.PublicKey
	Scope Scope
}

// Verdict is the result of checking a presented host key.
type Verdict int

const (
	// Unknown: no trust exists for this host; the user may decide.
	Unknown Verdict = iota
	// Trusted: the presented key is the effective key for its type.
	Trusted
	// Changed: trust exists for this host, but not for this key.
	Changed
	// Revoked: the presented key is revoked for this host.
	Revoked
)

func (v Verdict) String() string {
	switch v {
	case Trusted:
		return "trusted"
	case Changed:
		return "changed"
	case Revoked:
		return "revoked"
	default:
		return "unknown"
	}
}

// Trust is the layered view a connection uses: the user's own file first,
// then the global file. Either may be nil.
type Trust struct {
	User   *File
	Global *File
}

// LookupName is the name a host is stored under: the host for port 22,
// otherwise "[host]:port".
func LookupName(host string, port int) string {
	if port == 22 {
		return host
	}
	return "[" + host + "]:" + strconv.Itoa(port)
}

// HostPort splits a lookup name back into host and port, like the regular
// expression \[(.+)]:(\d+) of the Python store, where \d is any Unicode
// decimal digit. Port 0 means the name is hashed and the port is not
// recoverable.
func HostPort(name string) (string, int) {
	if strings.HasPrefix(name, hashedPrefix) {
		return "(hashed hostname)", 0
	}
	if i := strings.LastIndex(name, "]:"); strings.HasPrefix(name, "[") && i > 1 && !strings.Contains(name[1:i], "\n") {
		if port, ok := pyDecimal(name[i+2:]); ok {
			return name[1:i], port
		}
	}
	return name, 22
}

// pyDecimal parses a non-empty string of Unicode decimal digits as Python's
// int() does. Values that do not fit an int are refused.
func pyDecimal(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for _, r := range s {
		d, ok := decimalValue(r)
		if !ok || n > (math.MaxInt-d)/10 {
			return 0, false
		}
		n = n*10 + d
	}
	return n, true
}

// decimalValue returns the value of a Unicode decimal digit. Every range of
// the Nd table starts at a digit zero and runs in blocks of ten.
func decimalValue(r rune) (int, bool) {
	for _, rg := range unicode.Nd.R16 {
		if lo, hi := rune(rg.Lo), rune(rg.Hi); r >= lo && r <= hi && rg.Stride == 1 {
			return int(r-lo) % 10, true
		}
	}
	for _, rg := range unicode.Nd.R32 {
		if uint32(r) >= rg.Lo && uint32(r) <= rg.Hi && rg.Stride == 1 { // #nosec G115 -- r is a valid code point, never negative
			return int(uint32(r)-rg.Lo) % 10, true
		}
	}
	return 0, false
}

func (t Trust) layers() []struct {
	scope Scope
	file  *File
} {
	return []struct {
		scope Scope
		file  *File
	}{{ScopeUser, t.User}, {ScopeGlobal, t.Global}}
}

// Lookup returns the effective key per key type, in the order the types
// were first found (user file first, then global, each in file order).
// Revoked keys are skipped, so a later entry of the same type can apply.
func (t Trust) Lookup(name string) []TrustedKey {
	var known []TrustedKey
	for _, layer := range t.layers() {
		if layer.file == nil {
			continue
		}
		for _, entry := range layer.file.Trusted {
			if !entryMatches(name, entry) {
				continue
			}
			keyType := entry.Key.Type()
			if slices.ContainsFunc(known, func(k TrustedKey) bool { return k.Type == keyType }) {
				continue
			}
			if t.IsRevoked(name, entry.Key) {
				continue
			}
			known = append(known, TrustedKey{Type: keyType, Key: entry.Key, Scope: layer.scope})
		}
	}
	return known
}

// IsRevoked reports whether key is revoked for name in either store.
func (t Trust) IsRevoked(name string, key ssh.PublicKey) bool {
	blob := key.Marshal()
	for _, layer := range t.layers() {
		if layer.file == nil {
			continue
		}
		for _, entry := range layer.file.Revoked {
			if bytes.Equal(entry.Key.Marshal(), blob) && entryMatches(name, entry) {
				return true
			}
		}
	}
	return false
}

// Verify classifies a presented key. A revoked key is always reported as
// revoked, even when another key of the same type is trusted.
func (t Trust) Verify(name string, key ssh.PublicKey) Verdict {
	if t.IsRevoked(name, key) {
		return Revoked
	}
	known := t.Lookup(name)
	if len(known) == 0 {
		return Unknown
	}
	for _, k := range known {
		if k.Type == key.Type() {
			if bytes.Equal(k.Key.Marshal(), key.Marshal()) {
				return Trusted
			}
			return Changed
		}
	}
	return Changed
}

// PreferredAlgorithms orders allowed host-key algorithms so the types already
// trusted for name come first, which avoids a needless "changed" verdict when
// a server offers several host keys. Nothing is added to allowed.
func (t Trust) PreferredAlgorithms(name string, allowed []string) []string {
	var first []string
	for _, k := range t.Lookup(name) {
		for _, algo := range signatureAlgorithms(k.Type) {
			if slices.Contains(allowed, algo) && !slices.Contains(first, algo) {
				first = append(first, algo)
			}
		}
	}
	rest := slices.DeleteFunc(slices.Clone(allowed), func(a string) bool { return slices.Contains(first, a) })
	return append(first, rest...)
}

func signatureAlgorithms(keyType string) []string {
	if keyType == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	}
	return []string{keyType}
}
