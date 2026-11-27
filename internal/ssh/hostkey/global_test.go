package hostkey

import (
	"bytes"
	json "encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/store"
)

// The corpus is recorded from app/host_key_store.py by
// testdata/global_oracle.py.
type globalOracle struct {
	List []oracleListEntry `json:"list"`
	Adds []struct {
		Name   string           `json:"name"`
		Base   *string          `json:"base"`
		Value  any              `json:"value"`
		After  *string          `json:"after"`
		Error  string           `json:"error"`
		Status int              `json:"status"`
		Entry  *oracleListEntry `json:"entry"`
	} `json:"adds"`
	Deletes []struct {
		Name    string  `json:"name"`
		Base    *string `json:"base"`
		ID      string  `json:"id"`
		Removed bool    `json:"removed"`
		After   *string `json:"after"`
	} `json:"deletes"`
}

func readGlobalOracle(t *testing.T) globalOracle {
	t.Helper()
	raw, err := os.ReadFile("testdata/global_oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var o globalOracle
	if err := json.Unmarshal(raw, &o); err != nil {
		t.Fatal(err)
	}
	return o
}

func globalStore(t *testing.T, base *string) (*Store, *store.DB) {
	t.Helper()
	s, db := newStore(t)
	if base != nil {
		importRaw(t, db, ScopeGlobal, 0, *base)
	}
	return s, db
}

func globalRaw(t *testing.T, db *store.DB) *string {
	t.Helper()
	var raw []byte
	var found bool
	if err := db.Read(t.Context(), func(tx *store.Tx) error {
		var err error
		raw, found, err = FileTx(t.Context(), tx, ScopeGlobal, 0)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !found {
		return nil
	}
	s := string(raw)
	return &s
}

func sameListed(t *testing.T, name string, got Listed, want oracleListEntry) {
	t.Helper()
	if got.ID != want.ID || got.Algorithm != want.Algorithm || got.Fingerprint != want.Fingerprint || len(got.Hosts) != len(want.Hosts) {
		t.Fatalf("%s: got %+v, want %+v", name, got, want)
	}
	if (want.Marker == nil) != (got.Marker == MarkerNone) || (want.Marker != nil && string(got.Marker) != *want.Marker) {
		t.Fatalf("%s: marker %q, want %v", name, got.Marker, want.Marker)
	}
	for i, h := range want.Hosts {
		port := 0
		if h.Port != nil {
			port = *h.Port
		}
		if got.Hosts[i].Host != h.Host || got.Hosts[i].Port != port {
			t.Fatalf("%s: host %d = %+v, want %+v", name, i, got.Hosts[i], h)
		}
	}
}

func TestGlobalAddMatchesPython(t *testing.T) {
	o := readGlobalOracle(t)
	for _, c := range o.Adds {
		t.Run(c.Name, func(t *testing.T) {
			s, db := globalStore(t, c.Base)
			value, isText := c.Value.(string)
			var entry GlobalEntry
			var err error
			if isText {
				entry, err = s.GlobalAdd(t.Context(), value)
			} else {
				err = errEntryNotText // the route refuses it before the store
			}
			if c.Error != "" {
				status, _, message := fault.Status(err)
				if message != c.Error || status != c.Status {
					t.Fatalf("got %d %q (%v), want %d %q", status, message, err, c.Status, c.Error)
				}
			} else if err != nil {
				t.Fatal(err)
			} else {
				sameListed(t, c.Name, entry.Listed, *c.Entry)
			}
			after := globalRaw(t, db)
			if (after == nil) != (c.After == nil) || (after != nil && *after != *c.After) {
				t.Fatalf("file after: %q, want %q", fileText(after), fileText(c.After))
			}
		})
	}
}

func fileText(s *string) string {
	if s == nil {
		return "<none>"
	}
	return *s
}

func TestGlobalListAndDeleteMatchPython(t *testing.T) {
	o := readGlobalOracle(t)
	base := o.Deletes[0].Base
	s, _ := globalStore(t, base)
	listed, err := s.GlobalList(t.Context())
	if err != nil || len(listed) != len(o.List) {
		t.Fatalf("%d entries, %v", len(listed), err)
	}
	for i, want := range o.List {
		sameListed(t, "list", listed[i].Listed, want)
	}
	for _, c := range o.Deletes {
		t.Run(c.Name, func(t *testing.T) {
			s, db := globalStore(t, c.Base)
			has, err := s.GlobalHas(t.Context(), c.ID)
			if err != nil || has != c.Removed {
				t.Fatalf("has = %v, %v", has, err)
			}
			err = s.GlobalDelete(t.Context(), c.ID)
			if c.Removed != (err == nil) {
				t.Fatalf("delete: %v", err)
			}
			if !c.Removed && fault.CodeOf(err) != fault.NotFound {
				t.Fatalf("delete of an unknown entry: %v", err)
			}
			after := globalRaw(t, db)
			if (after == nil) != (c.After == nil) || (after != nil && *after != *c.After) {
				t.Fatalf("file after: %q, want %q", fileText(after), fileText(c.After))
			}
		})
	}
}

// A global entry applies to every user, below the user's own trust.
func TestGlobalAddTrustsEveryUser(t *testing.T) {
	s, _ := newStore(t)
	k := newKey(t)
	if _, err := s.GlobalAdd(t.Context(), "[shared.test]:2222 "+k.Type()+" "+lineKey(k)); err != nil {
		t.Fatal(err)
	}
	for _, owner := range []int64{1, 2} {
		if ok, err := s.Known(t.Context(), owner, "shared.test", 2222, k); !ok || err != nil {
			t.Fatalf("user %d: %v %v", owner, ok, err)
		}
	}
	if _, err := s.GlobalAdd(t.Context(), "@revoked [shared.test]:2222 "+k.Type()+" "+lineKey(k)); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.Known(t.Context(), 1, "shared.test", 2222, k); ok || fault.CodeOf(err) != fault.HostKeyRevoked {
		t.Fatalf("revoked: %v %v", ok, err)
	}
}

// A malformed global store is never extended: the administrator repairs
// it first.
func TestGlobalAddRefusesInvalidStore(t *testing.T) {
	bad := "not a host key line\n"
	s, db := globalStore(t, nil)
	if err := db.Write(t.Context(), func(tx *store.Tx) error {
		return writeFile(t.Context(), tx, ScopeGlobal, 0, []byte(bad), s.now())
	}); err != nil {
		t.Fatal(err)
	}
	k := newKey(t)
	if _, err := s.GlobalAdd(t.Context(), "a.test "+k.Type()+" "+lineKey(k)); fault.CodeOf(err) != fault.StorageError {
		t.Fatalf("add to an invalid store: %v", err)
	}
	if got := globalRaw(t, db); got == nil || *got != bad {
		t.Fatalf("store changed: %v", got)
	}
}

type recordingAudit struct{ events []string }

func (a *recordingAudit) Security(event string, kv ...any) { a.events = append(a.events, event) }

type globalFixture struct {
	mux    *http.ServeMux
	stepUp *principaltest.StepUp
	audit  *recordingAudit
	store  *Store
	admin  principal.Principal
}

func newGlobalFixture(t *testing.T, enabled bool) *globalFixture {
	t.Helper()
	s, _ := newStore(t)
	f := &globalFixture{mux: http.NewServeMux(), stepUp: &principaltest.StepUp{}, audit: &recordingAudit{}, store: s, admin: principaltest.Admin(9)}
	(&GlobalHTTP{Store: s, StepUp: f.stepUp, Audit: f.audit, Enabled: enabled}).Register(f.mux)
	return f
}

func (f *globalFixture) do(t *testing.T, p principal.Principal, method, path, body, grant string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequestWithContext(principal.With(t.Context(), p), method, path, strings.NewReader(body))
	if grant != "" {
		req.Header.Set(StepUpHeader, grant)
	}
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	var out map[string]any
	if rec.Header().Get("Content-Type") == "application/json" {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
	}
	return rec.Code, out
}

func TestGlobalHTTP(t *testing.T) {
	f := newGlobalFixture(t, true)
	k := newKey(t)
	line := "|1|AAECAwQFBgcICQoLDA0ODxAREhM=|" + "AAAAAAAAAAAAAAAAAAAAAAAAAAA=" + " " + k.Type() + " " + lineKey(k)
	body, _ := json.Marshal(map[string]string{"entry": line})

	// No grant: refused, nothing stored.
	if status, out := f.do(t, f.admin, "POST", "/admin/api/host-keys", string(body), ""); status != 403 || out["code"] != "step_up_required" {
		t.Fatalf("without grant: %d %v", status, out)
	}
	// An invalid entry does not spend the grant.
	f.stepUp.Issue(f.admin, principal.ActionHostKeyGlobalAdd, "global", "g1")
	if status, out := f.do(t, f.admin, "POST", "/admin/api/host-keys", `{"entry":"broken"}`, "g1"); status != 400 || out["error"] != "Invalid or unsupported known_hosts entry" {
		t.Fatalf("invalid entry: %d %v", status, out)
	}
	if status, out := f.do(t, f.admin, "POST", "/admin/api/host-keys", `{"entry":7}`, "g1"); status != 400 || out["error"] != "Host key entry must be text" {
		t.Fatalf("not text: %d %v", status, out)
	}
	if status, out := f.do(t, f.admin, "POST", "/admin/api/host-keys", `[1]`, "g1"); status != 400 || out["error"] != "Invalid request" {
		t.Fatalf("not an object: %d %v", status, out)
	}
	status, out := f.do(t, f.admin, "POST", "/admin/api/host-keys", string(body), "g1")
	entry, _ := out["entry"].(map[string]any)
	if status != 201 || entry["host"] != "(hashed hostname)" || entry["port"] != nil || entry["scope"] != "global" || entry["owner_id"] != nil {
		t.Fatalf("add: %d %v", status, out)
	}
	// The grant is single use.
	if status, _ := f.do(t, f.admin, "POST", "/admin/api/host-keys", string(body), "g1"); status != 403 {
		t.Fatalf("reused grant: %d", status)
	}
	f.stepUp.Issue(f.admin, principal.ActionHostKeyGlobalAdd, "global", "g2")
	if status, out := f.do(t, f.admin, "POST", "/admin/api/host-keys", string(body), "g2"); status != 409 || out["error"] != "Host key entry already exists" {
		t.Fatalf("duplicate: %d %v", status, out)
	}
	status, out = f.do(t, f.admin, "GET", "/admin/api/host-keys", "", "")
	if entries, _ := out["entries"].([]any); status != 200 || len(entries) != 1 {
		t.Fatalf("list: %d %v", status, out)
	}
	id, _ := entry["id"].(string)

	// Delete: an unknown id answers 404 before the grant is asked for; the
	// grant is bound to the entry id.
	if status, _ := f.do(t, f.admin, "DELETE", "/admin/api/host-keys/"+strings.Repeat("0", 64), "", ""); status != 404 {
		t.Fatalf("unknown id: %d", status)
	}
	f.stepUp.Issue(f.admin, principal.ActionHostKeyGlobalDelete, "other", "d1")
	if status, _ := f.do(t, f.admin, "DELETE", "/admin/api/host-keys/"+id, "", "d1"); status != 403 {
		t.Fatalf("grant for another target: %d", status)
	}
	f.stepUp.Issue(f.admin, principal.ActionHostKeyGlobalDelete, id, "d2")
	if status, out := f.do(t, f.admin, "DELETE", "/admin/api/host-keys/"+id, "", "d2"); status != 200 || out["ok"] != true {
		t.Fatalf("delete: %d %v", status, out)
	}
	if got := strings.Join(f.audit.events, ","); got != "GLOBAL_SSH_HOST_KEY_ADDED,GLOBAL_SSH_HOST_KEY_DELETED" {
		t.Fatalf("audit %s", got)
	}
}

// Only administrators reach the global store, even if a route were
// mounted without the edge's admin level; the switch hides it entirely.
func TestGlobalHTTPRefusesNonAdmins(t *testing.T) {
	f := newGlobalFixture(t, true)
	user := principaltest.User(3)
	f.stepUp.Issue(user, principal.ActionHostKeyGlobalAdd, "global", "g")
	k := newKey(t)
	body := `{"entry":"a.test ` + k.Type() + " " + lineKey(k) + `"}`
	for _, method := range []string{"GET", "POST"} {
		if status, _ := f.do(t, user, method, "/admin/api/host-keys", body, "g"); status != 403 {
			t.Fatalf("%s by a user: %d", method, status)
		}
	}
	recovery := f.admin
	recovery.Recovery = true
	if status, _ := f.do(t, recovery, "GET", "/admin/api/host-keys", "", ""); status != 403 {
		t.Fatalf("recovery session: %d", status)
	}
	if entries, _ := f.store.GlobalList(t.Context()); len(entries) != 0 {
		t.Fatal("a user changed the global store")
	}
	off := newGlobalFixture(t, false)
	if status, _ := off.do(t, off.admin, "GET", "/admin/api/host-keys", "", ""); status != 404 {
		t.Fatalf("switched off: %d", status)
	}
}

func TestCanonicalEntryNegative(t *testing.T) {
	k := newKey(t)
	good := "a.test " + k.Type() + " " + lineKey(k)
	for _, v := range []string{"", good + "\n", "@cert-authority " + good, "@x " + good, "a.test", "a.test " + k.Type() + " !!!"} {
		if _, _, err := canonicalEntry(v); err == nil {
			t.Fatalf("accepted %q", v)
		}
	}
	line, _, err := canonicalEntry("  " + good + "   trailing comment ")
	if err != nil || line != good {
		t.Fatalf("%q %v", line, err)
	}
	if !errors.Is(errEntryExists, errEntryExists) || bytes.Contains([]byte(line), []byte("comment")) {
		t.Fatal("comment kept")
	}
}
