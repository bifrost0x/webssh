package hostkey

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

// ErrInvalidFile marks a known_hosts file that cannot be used. As before,
// one bad line rejects the whole file: trust is never evaluated on a guess.
var ErrInvalidFile = errors.New("invalid known_hosts file")

// InvalidFileError names the line that made a file unusable, so the
// migration report and the administrator can point at it. Line is 0 when
// the file is not valid UTF-8.
type InvalidFileError struct {
	Line   int
	Reason error
}

func (e *InvalidFileError) Error() string {
	if e.Line == 0 {
		return fmt.Sprintf("invalid known_hosts file: %v", e.Reason)
	}
	return fmt.Sprintf("invalid known_hosts file: line %d: %v", e.Line, e.Reason)
}

// Is makes errors.Is(err, ErrInvalidFile) true.
func (e *InvalidFileError) Is(target error) bool { return target == ErrInvalidFile }

// Unwrap returns the reason.
func (e *InvalidFileError) Unwrap() error { return e.Reason }

var errUnicode = errors.New("invalid unicode")

// Marker is the optional leading @-marker of a known_hosts line.
type Marker string

const (
	MarkerNone          Marker = ""
	MarkerRevoked       Marker = "@revoked"
	MarkerCertAuthority Marker = "@cert-authority"
)

// Entry is one parsed known_hosts line.
type Entry struct {
	Marker   Marker
	Patterns []string
	Key      ssh.PublicKey
	Line     int
}

// File is a parsed known_hosts file. Raw is kept so writers can append
// without rewriting unrelated lines.
type File struct {
	Raw     []byte
	Trusted []Entry
	Revoked []Entry
	// CertAuthorities are parsed but not used for trust, as before.
	CertAuthorities []Entry
}

// keyTypeNames lists, per public-key format, the type strings accepted in
// the key-type column. They match what paramiko accepted, so existing files
// stay readable; the effective type always comes from the key blob.
var keyTypeNames = map[string][]string{
	ssh.KeyAlgoRSA: {
		ssh.KeyAlgoRSA, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512,
		ssh.CertAlgoRSAv01, ssh.CertAlgoRSASHA256v01, ssh.CertAlgoRSASHA512v01,
	},
	ssh.KeyAlgoECDSA256: {ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521},
	ssh.KeyAlgoECDSA384: {ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521},
	ssh.KeyAlgoECDSA521: {ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521},
	ssh.KeyAlgoED25519:  {ssh.KeyAlgoED25519},
}

// Parse reads a whole known_hosts file.
func Parse(raw []byte) (*File, error) {
	if !utf8.Valid(raw) {
		return nil, &InvalidFileError{Reason: errUnicode}
	}
	file := &File{Raw: raw}
	for index, rawLine := range pySplitTextLines(string(raw)) {
		lineNumber := index + 1
		line := pyStrip(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entry, err := parseLine(line)
		if err != nil {
			return nil, &InvalidFileError{Line: lineNumber, Reason: err}
		}
		entry.Line = lineNumber
		switch entry.Marker {
		case MarkerRevoked:
			file.Revoked = append(file.Revoked, entry)
		case MarkerCertAuthority:
			file.CertAuthorities = append(file.CertAuthorities, entry)
		default:
			file.Trusted = append(file.Trusted, entry)
		}
	}
	return file, nil
}

var (
	errMarker  = errors.New("unsupported marker")
	errFields  = errors.New("too few fields")
	errPattern = errors.New("invalid host pattern")
	errKey     = errors.New("invalid or unsupported key")
)

// parseLine parses one stripped, non-comment line. Fields after the key
// (comments) are ignored.
func parseLine(line string) (Entry, error) {
	fields := pyFields(line)
	var entry Entry
	if len(fields) > 0 && strings.HasPrefix(fields[0], "@") {
		switch Marker(fields[0]) {
		case MarkerRevoked, MarkerCertAuthority:
			entry.Marker = Marker(fields[0])
		default:
			return Entry{}, errMarker
		}
		fields = fields[1:]
	}
	if len(fields) < 3 {
		return Entry{}, errFields
	}
	entry.Patterns = strings.Split(fields[0], ",")
	for _, pattern := range entry.Patterns {
		if !validPattern(pattern) {
			return Entry{}, errPattern
		}
	}
	key, err := parseKey(fields[1], fields[2])
	if err != nil {
		return Entry{}, err
	}
	entry.Key = key
	return entry, nil
}

func parseKey(typeName, encoded string) (ssh.PublicKey, error) {
	blob, err := decodeBase64Lenient(encoded)
	if err != nil {
		return nil, errKey
	}
	key, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return nil, errKey
	}
	names, ok := keyTypeNames[key.Type()]
	if !ok {
		return nil, errKey
	}
	if slices.Contains(names, typeName) {
		return key, nil
	}
	return nil, errKey
}
