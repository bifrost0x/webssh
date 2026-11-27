package hostkey

import (
	"bytes"
	"context"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
)

// maxGlobalEntryBytes bounds one pasted known_hosts entry (UTF-8 bytes),
// as the Python release did.
const maxGlobalEntryBytes = 16384

// GlobalEntry is one line of the global trust store, which applies to
// every user (C-TRUST-04).
type GlobalEntry struct {
	Listed
	Modified time.Time
}

// The texts of the Python release; the page shows them.
var (
	errEntryNotText     = fault.New(fault.ValidationError, "Host key entry must be text")
	errEntryNotOne      = fault.New(fault.ValidationError, "Enter exactly one known_hosts entry")
	errEntryUnsupported = fault.New(fault.ValidationError, "Invalid or unsupported known_hosts entry")
	errEntryInvalid     = fault.New(fault.ValidationError, "Invalid known_hosts entry")
	errEntryExists      = fault.New(fault.Conflict, "Host key entry already exists")
	errEntryDifferent   = fault.New(fault.Conflict, "A different key already exists for this host and algorithm; verify and remove it first")
)

// GlobalList returns the entries of the global store in file order.
func (s *Store) GlobalList(ctx context.Context) ([]GlobalEntry, error) {
	var f rawFile
	err := s.db.Read(ctx, func(tx *store.Tx) error {
		var err error
		f, err = readFile(ctx, tx, ScopeGlobal, 0)
		return err
	})
	if err != nil {
		return nil, err
	}
	listed, err := List(f.raw, ScopeGlobal, "")
	if err != nil {
		return nil, s.unusable(ctx, ScopeGlobal, 0, err)
	}
	out := make([]GlobalEntry, len(listed))
	for i, l := range listed {
		out[i] = GlobalEntry{Listed: l, Modified: f.modified}
	}
	return out, nil
}

// canonicalEntry checks one pasted entry like add_file_entry and returns
// the line to store: the optional @revoked marker, the host patterns, the
// key type and the key, joined by single spaces; a comment is dropped.
// @cert-authority is refused: WebSSH does not use certificate authorities
// for trust, and storing one would suggest it does.
func canonicalEntry(value string) (string, Entry, error) {
	if value == "" || len(value) > maxGlobalEntryBytes || strings.ContainsAny(value, "\r\n") {
		return "", Entry{}, errEntryNotOne
	}
	if !utf8.ValidString(value) {
		return "", Entry{}, errEntryInvalid
	}
	fields := pyFields(pyStrip(value))
	marker := ""
	if len(fields) > 0 && strings.HasPrefix(fields[0], "@") {
		marker, fields = fields[0], fields[1:]
	}
	if (marker != "" && Marker(marker) != MarkerRevoked) || len(fields) < 3 {
		return "", Entry{}, errEntryUnsupported
	}
	line := strings.Join(fields[:3], " ")
	if marker != "" {
		line = marker + " " + line
	}
	entry, err := parseLine(line)
	if err != nil {
		return "", Entry{}, errEntryInvalid
	}
	return line, entry, nil
}

// identityToken compares host patterns as add_file_entry did: literal
// patterns case-folded, salted hashes as written, negation kept.
func identityToken(pattern string) string {
	negated := strings.HasPrefix(pattern, "!")
	p := strings.TrimPrefix(pattern, "!")
	if !strings.HasPrefix(p, hashedPrefix) {
		p = caseFold(p)
	}
	if negated {
		return "!" + p
	}
	return p
}

// caseFold approximates str.casefold() for host patterns: simple folding
// plus ß, the multi-character fold that host names can contain.
func caseFold(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case 'ß', 'ẞ':
			b.WriteString("ss")
		default:
			b.WriteRune(unicode.ToLower(unicode.ToUpper(r)))
		}
	}
	return b.String()
}

func overlapping(a, b []string) bool {
	tokens := make(map[string]bool, len(a))
	for _, p := range a {
		tokens[identityToken(p)] = true
	}
	for _, p := range b {
		if tokens[identityToken(p)] {
			return true
		}
	}
	return false
}

// duplicateOf refuses an entry whose hosts overlap an existing line with
// the same marker and key type: the same key exists already, or another
// key would compete with it.
func duplicateOf(existing *File, entry Entry) error {
	for _, coll := range [][]Entry{existing.Trusted, existing.Revoked} {
		for _, e := range coll {
			if e.Marker != entry.Marker || e.Key.Type() != entry.Key.Type() || !overlapping(e.Patterns, entry.Patterns) {
				continue
			}
			if bytes.Equal(e.Key.Marshal(), entry.Key.Marshal()) {
				return errEntryExists
			}
			return errEntryDifferent
		}
	}
	return nil
}

// GlobalAdd appends one verified entry to the global store. It refuses a
// malformed store, an entry that is not exactly one supported line and an
// entry that duplicates or competes with an existing one. Every other
// line stays byte for byte.
func (s *Store) GlobalAdd(ctx context.Context, value string) (GlobalEntry, error) {
	line, entry, err := canonicalEntry(value)
	if err != nil {
		return GlobalEntry{}, err
	}
	now := s.now()
	err = s.db.Write(ctx, func(tx *store.Tx) error {
		f, err := readFile(ctx, tx, ScopeGlobal, 0)
		if err != nil {
			return err
		}
		parsed, err := Parse(f.raw)
		if err != nil {
			return s.unusable(ctx, ScopeGlobal, 0, err)
		}
		if err := duplicateOf(parsed, entry); err != nil {
			return err
		}
		raw := append([]byte(nil), f.raw...)
		if len(raw) > 0 && raw[len(raw)-1] != '\n' {
			raw = append(raw, '\n')
		}
		raw = append(raw, line...)
		raw = append(raw, '\n')
		return writeFile(ctx, tx, ScopeGlobal, 0, raw, now)
	})
	if err != nil {
		return GlobalEntry{}, err
	}
	listed, err := List([]byte(line), ScopeGlobal, "")
	if err != nil || len(listed) != 1 {
		return GlobalEntry{}, fault.Wrap(fault.Internal, err, "")
	}
	return GlobalEntry{Listed: listed[0], Modified: now}, nil
}

// GlobalHas reports whether the global store holds entry id, so a caller
// can refuse an unknown id before spending a step-up grant.
func (s *Store) GlobalHas(ctx context.Context, id string) (bool, error) {
	entries, err := s.GlobalList(ctx)
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		if e.ID == id {
			return validID(id), nil
		}
	}
	return false, nil
}

// GlobalDelete removes every line with entry id from the global store.
// Unrelated lines stay byte for byte; an unknown id is not_found.
func (s *Store) GlobalDelete(ctx context.Context, id string) error {
	if !validID(id) {
		return errEntryNotFound
	}
	return s.db.Write(ctx, func(tx *store.Tx) error {
		f, err := readFile(ctx, tx, ScopeGlobal, 0)
		if err != nil {
			return err
		}
		if !f.present {
			return errEntryNotFound
		}
		kept, removed, err := withoutLine(f.raw, ScopeGlobal, "", id)
		if err != nil {
			return s.unusable(ctx, ScopeGlobal, 0, err)
		}
		if removed == nil {
			return errEntryNotFound
		}
		return writeFile(ctx, tx, ScopeGlobal, 0, kept, s.now())
	})
}
