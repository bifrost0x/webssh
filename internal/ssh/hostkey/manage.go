package hostkey

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
)

// Target is one SSH endpoint the user owns (a saved profile or jump host).
// The management views explain trust only for these, never for patterns a
// caller names: a global wildcard must not become an inventory oracle.
type Target struct {
	ID   string
	Name string
	Kind string // "ssh" or "jump"
	Host string
	Port int // 0 means 22
}

// Targets lists the SSH endpoints of a user (provided by internal/hosts).
type Targets interface {
	SSHTargets(ctx context.Context, owner int64) ([]Target, error)
}

// UserEntry is one line of the user's own trust store.
type UserEntry struct {
	Listed
	Owner    int64
	Modified time.Time
}

// KeyReport says how one stored key applies to a target.
type KeyReport struct {
	Scope       Scope
	Algorithm   string
	Fingerprint string
	Status      string // "effective", "overridden" or "revoked"
}

// TargetReport is the effective trust of one target.
type TargetReport struct {
	Target
	Keys []KeyReport
}

// Impact previews the deletion of one user entry.
type Impact struct {
	// Revision binds a later Delete to the state that was previewed.
	Revision   string
	Targets    []TargetReport
	Unresolved bool // the entry may cover hosts no saved target names
}

var (
	errEntryNotFound = fault.New(fault.NotFound, "Host key not found.")
	errTrustChanged  = fault.New(fault.PreconditionFailed, "Trust changed. Reload and review the deletion again.")
)

// List returns the user's own entries in file order.
func (s *Store) List(ctx context.Context, owner int64) ([]UserEntry, error) {
	f, err := s.read(ctx, owner)
	if err != nil {
		return nil, err
	}
	listed, err := List(f.user.raw, ScopeUser, OwnerString(owner))
	if err != nil {
		return nil, s.unusable(ctx, ScopeUser, owner, err)
	}
	out := make([]UserEntry, len(listed))
	for i, l := range listed {
		out[i] = UserEntry{Listed: l, Owner: owner, Modified: f.user.modified}
	}
	return out, nil
}

// Effective explains which stored keys apply to each target, in the order
// and with the revocation rules of the connection check.
func (s *Store) Effective(ctx context.Context, owner int64, targets []Target) ([]TargetReport, error) {
	f, err := s.read(ctx, owner)
	if err != nil {
		return nil, err
	}
	return reports(targets, f.globalParsed, f.userParsed), nil
}

func targetName(t Target) string {
	port := t.Port
	if port == 0 {
		port = 22
	}
	return LookupName(t.Host, port)
}

func reports(targets []Target, global, user *File) []TargetReport {
	layered := Trust{User: user, Global: global}
	out := make([]TargetReport, 0, len(targets))
	for _, t := range targets {
		name := targetName(t)
		effective := layered.Lookup(name)
		var selected []string
		report := TargetReport{Target: t, Keys: []KeyReport{}}
		if report.Port == 0 {
			report.Port = 22
		}
		for _, layer := range []struct {
			scope Scope
			file  *File
		}{{ScopeUser, user}, {ScopeGlobal, global}} {
			if layer.file == nil {
				continue
			}
			for _, coll := range []struct {
				entries []Entry
				revoked bool
			}{{layer.file.Trusted, false}, {layer.file.Revoked, true}} {
				for _, e := range coll.entries {
					if !entryMatches(name, e) {
						continue
					}
					algorithm := e.Key.Type()
					status := "overridden"
					switch {
					case coll.revoked || layered.IsRevoked(name, e.Key):
						status = "revoked"
					case !slices.Contains(selected, algorithm) && isEffective(effective, e):
						status = "effective"
						selected = append(selected, algorithm)
					}
					report.Keys = append(report.Keys, KeyReport{Scope: layer.scope, Algorithm: algorithm, Fingerprint: Fingerprint(e.Key), Status: status})
				}
			}
		}
		out = append(out, report)
	}
	return out
}

func isEffective(effective []TrustedKey, e Entry) bool {
	for _, k := range effective {
		if k.Type == e.Key.Type() {
			return bytes.Equal(k.Key.Marshal(), e.Key.Marshal())
		}
	}
	return false
}

// splitKeep splits like bytes.splitlines(keepends=True).
func splitKeep(raw []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\n' && raw[i] != '\r' {
			continue
		}
		if raw[i] == '\r' && i+1 < len(raw) && raw[i+1] == '\n' {
			i++
		}
		lines = append(lines, raw[start:i+1])
		start = i + 1
	}
	if start < len(raw) {
		lines = append(lines, raw[start:])
	}
	return lines
}

// entryOfLine parses one raw line for management: nil for blank lines and
// comments.
func entryOfLine(line []byte) (*Entry, error) {
	text := pyStrip(string(bytes.TrimRight(line, "\r\n")))
	if text == "" || strings.HasPrefix(text, "#") {
		return nil, nil
	}
	e, err := parseLine(text)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// without removes every line with entry id; it reports whether one was
// found. Unrelated lines are kept byte for byte.
func without(raw []byte, owner int64, id string) (kept []byte, removed *Entry, err error) {
	for _, line := range splitKeep(raw) {
		e, err := entryOfLine(line)
		if err != nil {
			return nil, nil, err
		}
		if e != nil && EntryID(ScopeUser, OwnerString(owner), bytes.TrimRight(line, "\r\n")) == id {
			removed = e
			continue
		}
		kept = append(kept, line...)
	}
	return kept, removed, nil
}

func validID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for i := range len(id) {
		if c := id[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func (s *Store) revision(owner int64, id string, f files) string {
	mac := hmac.New(sha256.New, s.revisionKey[:])
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(owner)) // #nosec G115 -- owner > 0, checked by load
	mac.Write(buf[:])
	mac.Write([]byte{0})
	mac.Write([]byte(id))
	g := sha256.Sum256(f.global.raw)
	u := sha256.Sum256(f.user.raw)
	mac.Write(g[:])
	mac.Write(u[:])
	return hex.EncodeToString(mac.Sum(nil))
}

// DeletionImpact previews deleting entry id of the user's store: which of
// the targets it affects and how their trust looks afterwards. Nothing is
// written.
func (s *Store) DeletionImpact(ctx context.Context, owner int64, id string, targets []Target) (Impact, error) {
	f, err := s.read(ctx, owner)
	if err != nil {
		return Impact{}, err
	}
	kept, removed, err := without(f.user.raw, owner, id)
	if err != nil {
		return Impact{}, s.unusable(ctx, ScopeUser, owner, err)
	}
	if removed == nil || !validID(id) {
		return Impact{}, errEntryNotFound
	}
	var affected []Target
	var names []string
	for _, t := range targets {
		names = append(names, targetName(t))
		if entryMatches(targetName(t), *removed) {
			affected = append(affected, t)
		}
	}
	unresolved := false
	for _, p := range removed.Patterns {
		if strings.HasPrefix(p, "!") {
			continue
		}
		if strings.ContainsAny(p, "*?") || !slices.ContainsFunc(names, func(n string) bool { return patternMatches(n, p) }) {
			unresolved = true
		}
	}
	remaining, err := Parse(kept)
	if err != nil {
		return Impact{}, s.unusable(ctx, ScopeUser, owner, err)
	}
	return Impact{Revision: s.revision(owner, id, f), Targets: reports(affected, f.globalParsed, remaining), Unresolved: unresolved}, nil
}

// Delete removes entry id from the user's store. With a revision from
// DeletionImpact the deletion fails with precondition_failed when trust
// changed since the preview.
func (s *Store) Delete(ctx context.Context, owner int64, id, revision string, checkRevision bool) error {
	return s.db.Write(ctx, func(tx *store.Tx) error {
		f, err := s.load(ctx, tx, owner)
		if err != nil {
			return err
		}
		if checkRevision && (!validID(revision) || !hmac.Equal([]byte(revision), []byte(s.revision(owner, id, f)))) {
			return errTrustChanged
		}
		if !validID(id) {
			return errEntryNotFound
		}
		kept, removed, err := without(f.user.raw, owner, id)
		if err != nil {
			return s.unusable(ctx, ScopeUser, owner, err)
		}
		if removed == nil {
			return errEntryNotFound
		}
		return writeFile(ctx, tx, ScopeUser, owner, kept, s.now())
	})
}

// pythonISOTime renders t like Python's datetime.isoformat() for an aware
// UTC datetime: microseconds only when not zero.
func pythonISOTime(t time.Time) string {
	t = t.UTC()
	s := t.Format("2006-01-02T15:04:05")
	if us := t.Nanosecond() / 1000; us != 0 {
		s += fmt.Sprintf(".%06d", us)
	}
	return s + "+00:00"
}
