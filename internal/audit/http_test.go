package audit

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
)

type memRetention struct {
	n   int
	err error
}

func (m *memRetention) SetAuditBackupCount(_ context.Context, n int) error {
	if m.err != nil {
		return m.err
	}
	m.n = n
	return nil
}

func newHTTP(t *testing.T) (*HTTP, *principaltest.StepUp, *memRetention, *http.ServeMux) {
	t.Helper()
	l, err := Open(t.TempDir(), Options{BackupCount: 5})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	su := &principaltest.StepUp{}
	ret := &memRetention{}
	h := &HTTP{Logger: l, Retention: ret, StepUp: su, Enabled: true}
	mux := http.NewServeMux()
	h.Register(mux)
	return h, su, ret, mux
}

func serve(mux *http.ServeMux, p *principal.Principal, method, target, body string, header map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	for k, v := range header {
		r.Header.Set(k, v)
	}
	if p != nil {
		r = r.WithContext(principal.With(r.Context(), *p))
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func TestHTTPRefusesNonAdminsAndDisabled(t *testing.T) {
	t.Parallel()
	h, _, _, mux := newHTTP(t)
	user := principaltest.User(2)
	for _, target := range []string{"/admin/api/audit", "/admin/api/audit/export"} {
		if w := serve(mux, &user, "GET", target, "", nil); w.Code != http.StatusForbidden {
			t.Errorf("%s as user: %d", target, w.Code)
		}
		if w := serve(mux, nil, "GET", target, "", nil); w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
			t.Errorf("%s anonymous: %d", target, w.Code)
		}
	}
	if w := serve(mux, &user, "POST", "/admin/api/audit/retention", `{"backup_count":3}`, nil); w.Code != http.StatusForbidden {
		t.Errorf("retention as user: %d", w.Code)
	}
	h.Enabled = false
	admin := principaltest.Admin(1)
	for _, target := range []string{"/admin/api/audit", "/admin/api/audit/export"} {
		if w := serve(mux, &admin, "GET", target, "", nil); w.Code != http.StatusNotFound {
			t.Errorf("%s disabled: %d", target, w.Code)
		}
	}
}

func TestExportHTTP(t *testing.T) {
	t.Parallel()
	h, _, _, mux := newHTTP(t)
	admin := principaltest.Admin(1)
	for target, want := range map[string]string{
		"/admin/api/audit/export?from=yesterday":                         `{"error":"Invalid audit export timestamp"}`,
		"/admin/api/audit/export?to=2026-13-01":                          `{"error":"Invalid audit export timestamp"}`,
		"/admin/api/audit/export?from=2026-11-03&to=2026-11-02T00:00:00": `{"error":"Invalid audit export range"}`,
	} {
		w := serve(mux, &admin, "GET", target, "", nil)
		if w.Code != http.StatusBadRequest || w.Body.String() != want {
			t.Errorf("%s: %d %s", target, w.Code, w.Body)
		}
	}
	h.Logger.Event(Info, "LOGIN_SUCCESS", F("user", "a"))
	w := serve(mux, &admin, "HEAD", "/admin/api/audit/export", "", nil)
	if w.Code != http.StatusOK || w.Body.Len() != 0 {
		t.Fatalf("HEAD: %d %q", w.Code, w.Body)
	}
	w = serve(mux, &admin, "GET", "/admin/api/audit/export?level=info", "", nil)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/x-ndjson" ||
		w.Header().Get("X-WebSSH-Audit-Completeness") != "complete-within-retained-logs" ||
		w.Header().Get("X-WebSSH-Audit-Scan-Limit") != "50000" || w.Header().Get("X-WebSSH-Audit-Truncated") != "false" ||
		w.Header().Get("Content-Disposition") != `attachment; filename="webssh-audit.jsonl"` {
		t.Fatalf("export: %d %v", w.Code, w.Header())
	}
	lines := strings.Split(strings.TrimSuffix(w.Body.String(), "\n"), "\n")
	// The export itself is audited first (not for HEAD): LOGIN_SUCCESS
	// and AUDIT_EXPORT.
	if w.Header().Get("X-WebSSH-Audit-Scanned") != "2" || len(lines) != 3 ||
		!strings.Contains(lines[1], "AUDIT_EXPORT | admin=") || !strings.Contains(lines[2], "LOGIN_SUCCESS") ||
		lines[0] != `{"type":"webssh_audit_export","scanned":2,"truncated":false,"scan_limit":50000}` {
		t.Fatalf("body: %v", lines)
	}
}

func TestViewHTTP(t *testing.T) {
	t.Parallel()
	h, _, _, mux := newHTTP(t)
	admin := principaltest.Admin(1)
	for range 3 {
		h.Logger.Event(Info, "LOGIN_SUCCESS", F("user", "a"))
	}
	h.Logger.Event(Warning, "RATE_LIMIT_EXCEEDED", F("ip", "x"))
	for target, want := range map[string]string{
		"/admin/api/audit?offset=1&limit=1":  `"limit":1,"offset":1,"total":4}`,
		"/admin/api/audit?limit=x&offset=2":  `"limit":100,"offset":0,"total":4}`,
		"/admin/api/audit?limit=9999":        `"limit":500,"offset":0,"total":4}`,
		"/admin/api/audit?level=warning":     `"limit":100,"offset":0,"total":1}`,
		"/admin/api/audit?q=LOGIN&offset=-3": `"limit":100,"offset":0,"total":3}`,
		"/admin/api/audit?offset=+1_0":       `"limit":100,"offset":10,"total":4}`,
	} {
		w := serve(mux, &admin, "GET", target, "", nil)
		if w.Code != http.StatusOK || !strings.HasSuffix(w.Body.String(), want) || !strings.HasPrefix(w.Body.String(), `{"items":[`) {
			t.Errorf("%s: %d %s", target, w.Code, w.Body)
		}
	}
}

func TestRetentionHTTP(t *testing.T) {
	t.Parallel()
	h, su, ret, mux := newHTTP(t)
	admin := principaltest.Admin(1)
	if w := serve(mux, &admin, "POST", "/admin/api/audit/retention", `{"backup_count":3}`, nil); w.Code == http.StatusOK || ret.n != 0 {
		t.Fatalf("without step-up: %d", w.Code)
	}
	post := func(body string) *httptest.ResponseRecorder {
		su.Issue(admin, principal.ActionAuditRetention, "global", "g")
		return serve(mux, &admin, "POST", "/admin/api/audit/retention", body, map[string]string{StepUpHeader: "g"})
	}
	for _, body := range []string{`{"backup_count":true}`, `{"backup_count":1.0}`, `{"backup_count":0}`, `{"backup_count":91}`, `{"backup_count":"5"}`, `{}`, `{"backup_count":1e1}`} {
		w := post(body)
		if w.Code != http.StatusBadRequest || w.Body.String() != `{"error":"backup_count must be an integer between 1 and 90"}` {
			t.Errorf("%s: %d %s", body, w.Code, w.Body)
		}
	}
	for _, body := range []string{`[]`, `nope`, ``} {
		if w := post(body); w.Code != http.StatusBadRequest || w.Body.String() != `{"error":"Invalid request"}` {
			t.Errorf("%q: %d %s", body, w.Code, w.Body)
		}
	}
	logs := filepath.Dir(h.Logger.path)
	for _, n := range []string{"1", "2", "3", "4"} {
		if err := os.WriteFile(filepath.Join(logs, FileName+"."+n), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if w := post(`{"backup_count":2}`); w.Code != http.StatusOK || w.Body.String() != `{"backup_count":2}` || ret.n != 2 {
		t.Fatalf("valid: %d %s", w.Code, w.Body)
	}
	if _, err := os.Stat(filepath.Join(logs, FileName+".3")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("rotated file beyond the count kept: %v", err)
	}
	ret.err = errors.New("disk full")
	if w := post(`{"backup_count":4}`); w.Code != http.StatusServiceUnavailable || w.Body.String() != `{"error":"Audit retention could not be saved"}` {
		t.Errorf("store failure: %d %s", w.Code, w.Body)
	}
	v, err := h.Logger.View(ViewQuery{Limit: 10, Query: "AUDIT_RETENTION_CHANGED"})
	if err != nil || v.Total != 1 || !strings.Contains(v.Items[0], "backup_count=2") {
		t.Errorf("audit event: %+v %v", v, err)
	}
}

// Lines across chunk boundaries, an overlong line and a missing final
// newline read back like Python's reverse reader.
func TestNewestFirstChunks(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "log")
	long := strings.Repeat("a", readChunk+17)
	huge := strings.Repeat("b", MaxLineBytes+1)
	content := "first\n" + long + "\n\n" + huge + "\nlast"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	var got []string
	if _, err := newestFirst(path, func(line []byte) bool {
		if line == nil {
			got = append(got, "<overlong>")
		} else {
			got = append(got, string(line))
		}
		return true
	}); err != nil {
		t.Fatal(err)
	}
	want := []string{"last", "<overlong>", long, "first"}
	if len(got) != len(want) {
		t.Fatalf("got %d lines", len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d: %.20q", i, got[i])
		}
	}
}

func FuzzDecodeLine(f *testing.F) {
	for _, l := range handLines {
		f.Add([]byte(l))
	}
	f.Add([]byte(`{"a":NaN,"a":[-Infinity,1e999,"\ud800"]}`))
	f.Fuzz(func(t *testing.T, line []byte) {
		v, err := decodeLine(decodeText(line))
		if err != nil {
			return
		}
		for _, e := range []encoding{exportLine, queryText, viewJSON} {
			var b strings.Builder
			e.encode(&b, v)
			again, err := decodeLine([]byte(b.String()))
			if err != nil {
				t.Fatalf("%s does not read back: %v", b.String(), err)
			}
			var c strings.Builder
			e.encode(&c, again)
			if c.String() != b.String() && e != viewJSON {
				t.Fatalf("not stable: %s vs %s", b.String(), c.String())
			}
		}
	})
}
