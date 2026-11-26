package legacy

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

// HostKey is one line of a known_hosts file of the Python release.
type HostKey struct {
	Marker      string   // "", "revoked" or "cert-authority"
	Hosts       []string // as written, e.g. "[host]:2222" for a non-default port
	Key         ssh.PublicKey
	Fingerprint string // "SHA256:<unpadded base64>", identical to app/host_key_store.py
}

// GlobalHostKeys reads DATA_DIR/known_hosts.
func (s *Source) GlobalHostKeys() ([]HostKey, error) {
	return s.hostKeys("known_hosts")
}

// UserHostKeys reads the known_hosts file of a user.
func (s *Source) UserHostKeys(userID int64) ([]HostKey, error) {
	return s.hostKeys(userDir(userID) + "/known_hosts")
}

func (s *Source) hostKeys(name string) ([]HostKey, error) {
	data, err := s.readFile(name)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	keys, err := parseKnownHosts(data)
	if err != nil {
		return nil, fmt.Errorf("legacy: %s: %w", name, err)
	}
	return keys, nil
}

// parseKnownHosts parses known_hosts as app/host_key_store.py
// _parse_raw does: the file must be UTF-8; blank lines and comments are
// skipped; any other line that does not parse fails the whole file, so no
// trusted or revoked key is dropped silently. "@cert-authority" lines are
// returned with their marker; Python ignores them with a warning, and the
// migration reports them.
func parseKnownHosts(data []byte) ([]HostKey, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("invalid UTF-8")
	}
	var keys []HostKey
	for n, line := range pythonSplitLines(string(data)) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		marker, hosts, key, _, rest, err := ssh.ParseKnownHosts([]byte(line))
		if err != nil || len(bytes.TrimSpace(rest)) != 0 || len(hosts) == 0 {
			return nil, fmt.Errorf("line %d: invalid known_hosts entry", n+1)
		}
		if slices.ContainsFunc(hosts, func(h string) bool { return !validHostPattern(h) }) {
			return nil, fmt.Errorf("line %d: invalid host pattern", n+1)
		}
		if marker != "" && marker != "revoked" && marker != "cert-authority" {
			return nil, fmt.Errorf("line %d: unsupported marker", n+1)
		}
		keys = append(keys, HostKey{Marker: marker, Hosts: hosts, Key: key, Fingerprint: ssh.FingerprintSHA256(key)})
	}
	return keys, nil
}

// pythonSplitLines splits like Python's str.splitlines().
func pythonSplitLines(s string) []string {
	var lines []string
	start := 0
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		switch runes[i] {
		case '\r':
			if i+1 < len(runes) && runes[i+1] == '\n' {
				lines = append(lines, string(runes[start:i]))
				i++
				start = i + 1
				continue
			}
			fallthrough
		case '\n', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
			lines = append(lines, string(runes[start:i]))
			start = i + 1
		}
	}
	if start < len(runes) {
		lines = append(lines, string(runes[start:]))
	}
	return lines
}

// validHostPattern mirrors app/host_key_store.py _host_pattern_is_valid:
// a non-empty pattern, optionally negated; a hashed pattern must be
// "|1|<base64 salt of 20 bytes>|<base64 digest of 20 bytes>".
func validHostPattern(pattern string) bool {
	pattern = strings.TrimPrefix(pattern, "!")
	if pattern == "" {
		return false
	}
	if !strings.HasPrefix(pattern, "|") {
		return true
	}
	fields := strings.Split(pattern, "|")
	if len(fields) != 4 || fields[0] != "" || fields[1] != "1" {
		return false
	}
	salt, err1 := base64.StdEncoding.DecodeString(fields[2])
	digest, err2 := base64.StdEncoding.DecodeString(fields[3])
	return err1 == nil && err2 == nil && len(salt) == 20 && len(digest) == 20
}
