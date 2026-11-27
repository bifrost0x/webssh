package hostops

import (
	"context"
	json "encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

type fakeProfiles map[int64][]string

func (f fakeProfiles) ProfileIDs(_ context.Context, owner int64) ([]string, error) {
	return slices.Clone(f[owner]), nil
}

type fakeSets map[string]bool

func (f fakeSets) SetExists(_ context.Context, _ int64, id string) (bool, error) { return f[id], nil }

func newContexts(t *testing.T, sets CommandSets) (*Contexts, *store.DB, fakeProfiles) {
	t.Helper()
	db := storetest.Open(t, Schema())
	profiles := fakeProfiles{1: {"p1", "p2"}, 2: {"q1"}}
	return &Contexts{DB: db, Profiles: profiles, Sets: sets}, db, profiles
}

func code(err error) string {
	if ce, ok := errors.AsType[*ContextError](err); ok {
		return ce.Code
	}
	if err != nil {
		return "error: " + err.Error()
	}
	return ""
}

// The corpus is recorded from app/host_context.py and its route by
// testdata/context_oracle.py.
type contextOracle struct {
	Cases []struct {
		Name     string `json:"name"`
		Body     string `json:"body"`
		Decision string `json:"decision"`
	} `json:"cases"`
	Sizes []struct {
		Content struct {
			Notes       string   `json:"notes"`
			Directories []string `json:"directories"`
			CommandSets []string `json:"command_sets"`
		} `json:"content"`
		ContentSize   int `json:"content_size"`
		DocumentSize  int `json:"document_size"`
		EmptyDocument int `json:"empty_document_size"`
	} `json:"sizes"`
}

func readContextOracle(t *testing.T) contextOracle {
	t.Helper()
	raw, err := os.ReadFile("testdata/context_oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var o contextOracle
	if err := json.Unmarshal(raw, &o); err != nil {
		t.Fatal(err)
	}
	return o
}

// The request rules match the Python route case by case.
func TestContextRequestRulesMatchPython(t *testing.T) {
	for _, c := range readContextOracle(t).Cases {
		t.Run(c.Name, func(t *testing.T) {
			req := httptest.NewRequest("PUT", "/api/profiles/p1/context", strings.NewReader(c.Body))
			req.Header.Set("Content-Type", "application/json")
			content, _, err := readContext(httptest.NewRecorder(), req)
			got := "ok"
			if err != nil || !validContent(content) || contentSize(content) > MaxContextContent {
				got = "invalid"
			}
			if got != c.Decision {
				t.Fatalf("got %s, want %s (%v)", got, c.Decision, err)
			}
		})
	}
}

// The quota measures the document the way Python wrote it.
func TestContextSizesMatchPython(t *testing.T) {
	for i, s := range readContextOracle(t).Sizes {
		c := Content{Notes: s.Content.Notes, Directories: s.Content.Directories, CommandSets: s.Content.CommandSets}
		if got := contentSize(c); got != s.ContentSize {
			t.Fatalf("case %d: content size %d, want %d", i, got, s.ContentSize)
		}
		if s.EmptyDocument != contextDocumentPrefix {
			t.Fatalf("empty document %d, want %d", contextDocumentPrefix, s.EmptyDocument)
		}
		size := contextDocumentPrefix
		for index := range 3 {
			if index > 0 {
				size += 2
			}
			size += entrySize("profile-"+strconv.Itoa(index)+"-ü", HostContext{Content: c, Revision: []int64{1, 10, 100}[index]})
		}
		if size != s.DocumentSize {
			t.Fatalf("case %d: document size %d, want %d", i, size, s.DocumentSize)
		}
	}
}

func TestContextLifecycle(t *testing.T) {
	c, _, _ := newContexts(t, fakeSets{"set-a": true})
	ctx := t.Context()
	hc, err := c.Read(ctx, 1, "p1")
	if err != nil || hc.Revision != 0 || hc.Notes != "" || len(hc.Directories) != 0 || hc.Directories == nil {
		t.Fatalf("empty: %+v %v", hc, err)
	}
	want := Content{Notes: "deploy", Directories: []string{"/var/log", "/etc"}, CommandSets: []string{"set-a"}}
	hc, err = c.Write(ctx, 1, "p1", want, 0)
	if err != nil || hc.Revision != 1 {
		t.Fatalf("write: %+v %v", hc, err)
	}
	if _, err := c.Write(ctx, 1, "p1", want, 0); code(err) != "conflict" {
		t.Fatalf("stale revision: %v", err)
	}
	got, err := c.Read(ctx, 1, "p1")
	if err != nil || got.Revision != 1 || got.Notes != "deploy" || !slices.Equal(got.Directories, want.Directories) || !slices.Equal(got.CommandSets, want.CommandSets) {
		t.Fatalf("read back: %+v %v", got, err)
	}
	// Clearing the notes keeps the revision.
	if hc, err = c.Write(ctx, 1, "p1", Content{}, 1); err != nil || hc.Revision != 2 {
		t.Fatalf("clear: %+v %v", hc, err)
	}
	if got, _ := c.Read(ctx, 1, "p1"); got.Revision != 2 || got.Notes != "" || len(got.Directories) != 0 {
		t.Fatalf("cleared: %+v", got)
	}
	// Another user's or an unknown profile is not found, never created.
	for _, tc := range []struct {
		owner int64
		id    string
	}{{2, "p1"}, {1, "q1"}, {1, "missing"}, {1, ""}, {1, strings.Repeat("p", 129)}} {
		if _, err := c.Read(ctx, tc.owner, tc.id); code(err) != "not_found" {
			t.Fatalf("read %d/%q: %v", tc.owner, tc.id, err)
		}
		if _, err := c.Write(ctx, tc.owner, tc.id, Content{}, 0); code(err) != "not_found" {
			t.Fatalf("write %d/%q: %v", tc.owner, tc.id, err)
		}
	}
	if _, err := c.Write(ctx, 1, "p1", Content{CommandSets: []string{"unknown"}}, 2); code(err) != "invalid_reference" {
		t.Fatalf("unknown set: %v", err)
	}
	if _, err := c.Write(ctx, 1, "p1", Content{Directories: []string{"relative"}}, 2); code(err) != "invalid" {
		t.Fatalf("relative directory: %v", err)
	}
}

// Without the command library only references that are stored already
// are accepted: a save neither drops nor invents one.
func TestContextReferencesWithoutLibrary(t *testing.T) {
	c, db, _ := newContexts(t, nil)
	ctx := t.Context()
	if err := db.Write(ctx, func(tx *store.Tx) error {
		return ImportContext(ctx, tx, 1, "p1", []string{"/srv"}, []string{"legacy-set"}, 7)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(ctx, 1, "p1", Content{CommandSets: []string{"legacy-set", "new"}}, 7); code(err) != "invalid_reference" {
		t.Fatalf("new reference: %v", err)
	}
	hc, err := c.Write(ctx, 1, "p1", Content{Notes: "x", Directories: []string{"/srv"}, CommandSets: []string{"legacy-set"}}, 7)
	if err != nil || hc.Revision != 8 {
		t.Fatalf("kept reference: %+v %v", hc, err)
	}
}

// A context migrated by an earlier build with only a note continues the
// note's revision.
func TestContextRevisionContinuesFromNote(t *testing.T) {
	c, db, _ := newContexts(t, nil)
	ctx := t.Context()
	if err := db.Write(ctx, func(tx *store.Tx) error { return ImportNote(ctx, tx, 1, "p2", "old", 41) }); err != nil {
		t.Fatal(err)
	}
	hc, err := c.Read(ctx, 1, "p2")
	if err != nil || hc.Revision != 41 || hc.Notes != "old" {
		t.Fatalf("%+v %v", hc, err)
	}
	if _, err := c.Write(ctx, 1, "p2", Content{Notes: "new"}, 40); code(err) != "conflict" {
		t.Fatalf("stale: %v", err)
	}
	if hc, err = c.Write(ctx, 1, "p2", Content{Notes: "new"}, 41); err != nil || hc.Revision != 42 {
		t.Fatalf("%+v %v", hc, err)
	}
	if body, rev, found, _ := noteOf(t, db, 1, "p2"); !found || body != "new" || rev != 42 {
		t.Fatalf("note row %q %d %v", body, rev, found)
	}
}

func noteOf(t *testing.T, db *store.DB, owner int64, id string) (body string, rev int64, found bool, err error) {
	t.Helper()
	err = db.Read(t.Context(), func(tx *store.Tx) error {
		body, rev, found, err = NoteTx(t.Context(), tx, owner, id)
		return err
	})
	return body, rev, found, err
}

// A write removes the contexts of deleted profiles, as Python pruned them.
func TestContextPrunesDeletedProfiles(t *testing.T) {
	c, db, profiles := newContexts(t, nil)
	ctx := t.Context()
	if _, err := c.Write(ctx, 1, "p2", Content{Notes: "gone soon", Directories: []string{"/x"}}, 0); err != nil {
		t.Fatal(err)
	}
	profiles[1] = []string{"p1"}
	if _, err := c.Write(ctx, 1, "p1", Content{Notes: "kept"}, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, found, _ := noteOf(t, db, 1, "p2"); found {
		t.Fatal("note of a deleted profile kept")
	}
	var n int
	if err := db.Read(ctx, func(tx *store.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM hostops_host_context WHERE profile_id = 'p2'`).Scan(&n)
	}); err != nil || n != 0 {
		t.Fatalf("context of a deleted profile kept: %d %v", n, err)
	}
}

func TestContextQuota(t *testing.T) {
	c, db, profiles := newContexts(t, nil)
	ctx := t.Context()
	ids := make([]string, 0, MaxHostContexts+1)
	for i := range MaxHostContexts + 1 {
		ids = append(ids, "p"+strconv.Itoa(i))
	}
	profiles[1] = ids
	if err := db.Write(ctx, func(tx *store.Tx) error {
		for _, id := range ids[:MaxHostContexts] {
			if err := ImportContext(ctx, tx, 1, id, nil, nil, 1); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(ctx, 1, ids[MaxHostContexts], Content{}, 0); code(err) != "quota" {
		t.Fatalf("2001st context: %v", err)
	}
	if _, err := c.Write(ctx, 1, ids[0], Content{Notes: "fits"}, 1); err != nil {
		t.Fatalf("update below the limit: %v", err)
	}
	// Byte limit: eight contexts of 512 KiB exceed 4 MiB.
	big := Content{Notes: strings.Repeat("\x01", 85000)}
	var err error
	for _, id := range ids[1:10] {
		if _, err = c.Write(ctx, 1, id, big, 1); err != nil {
			break
		}
	}
	if code(err) != "quota" {
		t.Fatalf("byte limit: %v", err)
	}
}

func TestContextHTTP(t *testing.T) {
	c, _, _ := newContexts(t, fakeSets{})
	mux := http.NewServeMux()
	(&ContextHTTP{Contexts: c}).Register(mux)
	do := func(method, path, contentType, body string) (int, map[string]any) {
		req := httptest.NewRequestWithContext(principal.With(t.Context(), principal.Principal{UserID: 1, SessionID: "s"}), method, path, strings.NewReader(body))
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s %s: %s", method, path, rec.Body.String())
		}
		return rec.Code, out
	}
	status, out := do("GET", "/api/profiles/p1/context", "", "")
	if status != 200 || out["revision"] != 0.0 || out["notes"] != "" {
		t.Fatalf("get: %d %v", status, out)
	}
	if dirs, ok := out["directories"].([]any); !ok || len(dirs) != 0 {
		t.Fatalf("directories not an empty list: %v", out)
	}
	body := `{"revision": 0, "notes": "n", "directories": ["/a"], "command_sets": []}`
	if status, out = do("PUT", "/api/profiles/p1/context", "text/plain", body); status != 400 || out["code"] != "invalid" {
		t.Fatalf("wrong content type: %d %v", status, out)
	}
	if status, out = do("PUT", "/api/profiles/p1/context", "application/json", body); status != 200 || out["revision"] != 1.0 {
		t.Fatalf("put: %d %v", status, out)
	}
	if status, out = do("PUT", "/api/profiles/p1/context", "application/json", body); status != 409 || out["code"] != "conflict" || out["error"] != contextErrorText {
		t.Fatalf("conflict: %d %v", status, out)
	}
	if status, out = do("GET", "/api/profiles/other/context", "", ""); status != 404 || out["code"] != "not_found" {
		t.Fatalf("not found: %d %v", status, out)
	}
	if status, out = do("PUT", "/api/profiles/p1/context", "application/json", `{"revision": 1, "notes": "", "directories": [], "command_sets": ["x"]}`); status != 400 || out["code"] != "invalid_reference" {
		t.Fatalf("reference: %d %v", status, out)
	}
}
