package legacy

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/store"
)

// hostNotesStep migrates the notes of entity E28, users/user_N/
// host_context.json, into hostops_notes with the context's revision
// (D-11, specification 4.5). The directories and command-set references
// of a host context follow with the command sets in a later build; until
// then they stay in the legacy file and are reported. Contexts of
// profiles that no longer exist stay in place: Python never shows them.
type hostNotesStep struct {
	notes   []note
	kept    []KeptPath
	pending int // contexts with directories or command-set references
	orphans int
}

// maxHostContexts is MAX_HOST_CONTEXTS of app/host_context.py.
const maxHostContexts = 2000

func (*hostNotesStep) Entity() string { return "E28" }

// countHostContextsLeft counts the host contexts whose directories or
// command-set references stay in the legacy file, and those of deleted
// profiles: the part of E28 a later phase migrates.
func countHostContextsLeft(ctx context.Context, src *Source) (int, error) {
	var s hostNotesStep
	if err := s.Read(ctx, src); err != nil {
		return 0, err
	}
	return s.pending + s.orphans, nil
}

func (*hostNotesStep) Version() int { return 1 }

func (s *hostNotesStep) Read(ctx context.Context, src *Source) error {
	rows, err := src.AccountRows(ctx)
	if err != nil {
		return err
	}
	for _, a := range rows {
		doc, found, err := userStore(src, a.ID, "host_context")
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		profiles, err := profileIDs(src, a.ID)
		if err != nil {
			return err
		}
		if err := s.readContexts(a.ID, doc.Raw, profiles); err != nil {
			return &StepError{UserID: a.ID, Record: "host_context.json", Err: err}
		}
	}
	return nil
}

func profileIDs(src *Source, userID int64) ([]string, error) {
	doc, found, err := userStore(src, userID, "profiles")
	if err != nil || !found {
		return nil, err
	}
	items, err := doc.RawList("profiles")
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, p := range items {
		if v, ok := pyjson.Get(p, "id"); ok {
			if id, ok := pyString(v); ok {
				ids = append(ids, id)
			}
		}
	}
	return ids, nil
}

// readContexts checks the document like _valid_document of
// app/host_context.py (Python shows an invalid file as damaged: STOP) and
// collects the notes.
func (s *hostNotesStep) readContexts(userID int64, raw jsontext.Value, profiles []string) error {
	invalid := errors.New("legacy: host_context.json is not a valid host context document")
	if v, _ := pyjson.Get(raw, "version"); string(v) != "1" {
		return invalid
	}
	hostsValue, _ := pyjson.Get(raw, "hosts")
	contexts, ok := pyjson.Members(hostsValue)
	if !ok || len(contexts) > maxHostContexts {
		return invalid
	}
	keptFile := false
	for _, c := range contexts {
		body, revision, refs, ok := hostContext(c)
		if !ok || utf8.RuneCountInString(c.Name) > 128 {
			return invalid
		}
		if !slices.Contains(profiles, c.Name) {
			s.orphans++
			keptFile = true
			continue
		}
		if refs {
			s.pending++
			keptFile = true
		}
		if body != "" {
			s.notes = append(s.notes, note{userID: userID, profileID: c.Name, body: body, revision: revision})
		}
	}
	if keptFile {
		s.kept = append(s.kept, KeptPath{Path: userDir(userID) + "/host_context.json", Reason: "host_context_directories_and_orphans"})
	}
	return nil
}

// hostContext checks one context like _valid_content and returns its
// notes, revision and whether it holds directories or command sets.
func hostContext(c pyjson.Member) (body string, revision int64, refs, ok bool) {
	members, isObject := pyjson.Members(c.Value)
	if !isObject || len(members) != 4 {
		return "", 0, false, false
	}
	var dirs, sets []string
	seen := 0
	for _, m := range members {
		switch m.Name {
		case "revision":
			n, valid := Number(string(m.Value)).Int64()
			if m.Value.Kind() != '0' || !valid || n < 1 {
				return "", 0, false, false
			}
			revision, seen = n, seen+1
		case "notes":
			text, valid := pyString(m.Value)
			if m.Value.Kind() != '"' || !valid || utf8.RuneCountInString(text) > 100000 {
				return "", 0, false, false
			}
			body, seen = text, seen+1
		case "directories", "command_sets":
			list, valid := stringList(m.Value)
			if !valid {
				return "", 0, false, false
			}
			if m.Name == "directories" {
				dirs = list
			} else {
				sets = list
			}
			seen++
		}
	}
	if seen != 4 {
		return "", 0, false, false
	}
	for _, d := range dirs {
		if !strings.HasPrefix(d, "/") || len(d) > 4096 || strings.IndexFunc(d, func(r rune) bool { return !unicode.IsPrint(r) }) >= 0 {
			return "", 0, false, false
		}
	}
	for _, r := range sets {
		if n := utf8.RuneCountInString(r); n == 0 || n > 128 {
			return "", 0, false, false
		}
	}
	return body, revision, len(dirs) > 0 || len(sets) > 0, true
}

// stringList is a list of at most 20 distinct strings.
func stringList(v jsontext.Value) ([]string, bool) {
	items, ok := pyjson.Items(v)
	if !ok || len(items) > 20 {
		return nil, false
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		s, ok := pyString(it)
		if it.Kind() != '"' || !ok || slices.Contains(out, s) {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

func (s *hostNotesStep) Write(ctx context.Context, tx *store.Tx, _ Sealer) error {
	return importNotes(ctx, tx, s.notes)
}

func (s *hostNotesStep) Verify(ctx context.Context, tx *store.Tx, _ Opener) error {
	return verifyNotes(ctx, tx, s.notes)
}

func (s *hostNotesStep) Report() StepReport {
	r := StepReport{Entity: "E28", Version: 1, Read: len(s.notes), Written: len(s.notes), KeptInPlace: s.kept}
	if s.pending > 0 {
		r.Warnings = append(r.Warnings, Warning{Code: "host_context_pending", Count: s.pending,
			Message: "directories and command-set references of host contexts stay in the legacy file until the command sets are migrated"})
	}
	if s.orphans > 0 {
		r.Notes = append(r.Notes, "host contexts of deleted profiles stay in the legacy file; the Python release never showed them")
	}
	return r
}
