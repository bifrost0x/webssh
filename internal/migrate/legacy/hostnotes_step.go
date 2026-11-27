package legacy

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/hostops"
	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/store"
)

// hostNotesStep migrates entity E28, users/user_N/host_context.json: the
// notes into hostops_notes and the directories and command-set references
// into hostops_host_context, both with the context's revision, so an edit
// with the last revision the page saw still succeeds (D-11, specification
// 4.5). The references are kept as stored; the command sets they name are
// entity E27. Contexts of profiles that no longer exist stay in place:
// Python never shows them.
type hostNotesStep struct {
	notes    []note
	contexts []hostContextRecord
	kept     []KeptPath
	orphans  int
}

// hostContextRecord is the rest of one migrated host context.
type hostContextRecord struct {
	userID      int64
	profileID   string
	directories []string
	commandSets []string
	revision    int64
}

// maxHostContexts is MAX_HOST_CONTEXTS of app/host_context.py.
const maxHostContexts = 2000

func (*hostNotesStep) Entity() string { return "E28" }

func (*hostNotesStep) Version() int { return 2 }

func (*hostNotesStep) accountScoped() bool { return true }

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
	if v, _ := pyjson.Get(raw, "version"); !pyjson.EqualsOne(v) {
		return invalid
	}
	hostsValue, _ := pyjson.Get(raw, "hosts")
	contexts, ok := pyjson.Members(hostsValue)
	if !ok || len(contexts) > maxHostContexts {
		return invalid
	}
	keptFile := false
	for _, c := range contexts {
		body, revision, dirs, sets, ok := hostContext(c)
		if !ok || utf8.RuneCountInString(c.Name) > 128 {
			return invalid
		}
		if !slices.Contains(profiles, c.Name) {
			s.orphans++
			keptFile = true
			continue
		}
		s.contexts = append(s.contexts, hostContextRecord{userID: userID, profileID: c.Name, directories: dirs, commandSets: sets, revision: revision})
		if body != "" {
			s.notes = append(s.notes, note{userID: userID, profileID: c.Name, body: body, revision: revision})
		}
	}
	if keptFile {
		s.kept = append(s.kept, KeptPath{Path: userDir(userID) + "/host_context.json", Reason: "host_context_of_deleted_profiles"})
	}
	return nil
}

// hostContext checks one context like _valid_content and returns its
// notes, revision, directories and command-set references.
func hostContext(c pyjson.Member) (body string, revision int64, dirs, sets []string, ok bool) {
	members, isObject := pyjson.Members(c.Value)
	if !isObject || len(members) != 4 {
		return "", 0, nil, nil, false
	}
	seen := 0
	for _, m := range members {
		switch m.Name {
		case "revision":
			n, valid := Number(string(m.Value)).Int64()
			if m.Value.Kind() != '0' || !valid || n < 1 {
				return "", 0, nil, nil, false
			}
			revision, seen = n, seen+1
		case "notes":
			text, valid := pyString(m.Value)
			if m.Value.Kind() != '"' || !valid || utf8.RuneCountInString(text) > 100000 {
				return "", 0, nil, nil, false
			}
			body, seen = text, seen+1
		case "directories", "command_sets":
			list, valid := stringList(m.Value)
			if !valid {
				return "", 0, nil, nil, false
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
		return "", 0, nil, nil, false
	}
	for _, d := range dirs {
		if !strings.HasPrefix(d, "/") || len(d) > 4096 || strings.IndexFunc(d, func(r rune) bool { return !unicode.IsPrint(r) }) >= 0 {
			return "", 0, nil, nil, false
		}
	}
	for _, r := range sets {
		if n := utf8.RuneCountInString(r); n == 0 || n > 128 {
			return "", 0, nil, nil, false
		}
	}
	return body, revision, dirs, sets, true
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
	if err := importNotes(ctx, tx, s.notes); err != nil {
		return err
	}
	for _, c := range s.contexts {
		if err := hostops.ImportContext(ctx, tx, c.userID, c.profileID, c.directories, c.commandSets, c.revision); err != nil {
			return &StepError{UserID: c.userID, Record: c.profileID, Err: err}
		}
	}
	return nil
}

// Verify reads every migrated context back through the store of
// internal/hostops: notes, directories, references and revision equal.
func (s *hostNotesStep) Verify(ctx context.Context, tx *store.Tx, _ Opener) error {
	if err := verifyNotes(ctx, tx, s.notes); err != nil {
		return err
	}
	for _, c := range s.contexts {
		got, found, err := hostops.ContextTx(ctx, tx, c.userID, c.profileID)
		if err != nil {
			return &StepError{UserID: c.userID, Record: c.profileID, Err: err}
		}
		if !found || got.Revision != c.revision || !slices.Equal(got.Directories, nonNilList(c.directories)) ||
			!slices.Equal(got.CommandSets, nonNilList(c.commandSets)) {
			return &StepError{UserID: c.userID, Record: c.profileID, Err: errors.New("legacy: migrated host context differs")}
		}
	}
	return nil
}

func nonNilList(list []string) []string {
	if list == nil {
		return []string{}
	}
	return list
}

func (s *hostNotesStep) Report() StepReport {
	r := StepReport{Entity: "E28", Version: 2, Read: len(s.contexts), Written: len(s.contexts), KeptInPlace: s.kept}
	if s.orphans > 0 {
		r.Notes = append(r.Notes, "host contexts of deleted profiles stay in the legacy file; the Python release never showed them")
	}
	return r
}
