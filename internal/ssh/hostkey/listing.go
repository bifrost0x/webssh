package hostkey

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Fingerprint is the SHA256 fingerprint in OpenSSH notation, as WebSSH has
// always shown it ("SHA256:" and unpadded base64).
func Fingerprint(key ssh.PublicKey) string {
	return ssh.FingerprintSHA256(key)
}

// HostRef is one host of a listed entry. Port 0 means a hashed name.
type HostRef struct {
	Host string
	Port int
}

// Listed is the management view of one stored line.
type Listed struct {
	ID          string
	Hosts       []HostRef
	Marker      Marker
	Algorithm   string
	Fingerprint string
}

// List returns the management entries of a raw file. Owner is empty for
// the global file. IDs are stable across versions: the SHA-256 of scope,
// owner and the raw line bytes, so links and pending deletions keep working.
func List(raw []byte, scope Scope, owner string) ([]Listed, error) {
	var out []Listed
	for _, rawLine := range pySplitByteLines(raw) {
		line := pyStrip(string(rawLine))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entry, err := parseLine(line)
		if err != nil {
			return nil, ErrInvalidFile
		}
		listed := Listed{
			ID:          EntryID(scope, owner, rawLine),
			Marker:      entry.Marker,
			Algorithm:   entry.Key.Type(),
			Fingerprint: Fingerprint(entry.Key),
		}
		for _, pattern := range entry.Patterns {
			host, port := HostPort(pattern)
			listed.Hosts = append(listed.Hosts, HostRef{Host: host, Port: port})
		}
		out = append(out, listed)
	}
	return out, nil
}

// EntryID identifies one raw line of one store.
func EntryID(scope Scope, owner string, rawLine []byte) string {
	sum := sha256.New()
	sum.Write([]byte(scope))
	sum.Write([]byte{0})
	sum.Write([]byte(owner))
	sum.Write([]byte{0})
	sum.Write(rawLine)
	return hex.EncodeToString(sum.Sum(nil))
}

// FormatLine is the line appended when a user accepts a new host key.
func FormatLine(name string, key ssh.PublicKey) string {
	return name + " " + key.Type() + " " + base64.StdEncoding.EncodeToString(key.Marshal()) + "\n"
}

// OwnerString renders a numeric owner the way IDs have always included it.
func OwnerString(userID int64) string {
	return strconv.FormatInt(userID, 10)
}
