package hosts

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/store"
)

func TestShlexAndLinesMatchPython(t *testing.T) {
	raw, err := os.ReadFile("testdata/exchange_oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Shlex []struct {
			Line   string   `json:"line"`
			Tokens []string `json:"tokens"`
			Error  bool     `json:"error"`
		} `json:"shlex"`
		Lines []struct {
			Text  string   `json:"text"`
			Lines []string `json:"lines"`
		} `json:"splitlines"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	for _, tc := range c.Shlex {
		got, err := shlexSplit(tc.Line)
		if tc.Error != (err != nil) || (!tc.Error && !slices.Equal(nonNilStrings(got), nonNilStrings(tc.Tokens))) {
			t.Errorf("shlex %q = %q, %v; want %q (error %v)", tc.Line, got, err, tc.Tokens, tc.Error)
		}
	}
	for _, tc := range c.Lines {
		if got := pySplitLines(tc.Text); !slices.Equal(nonNilStrings(got), nonNilStrings(tc.Lines)) {
			t.Errorf("splitlines %q = %q, want %q", tc.Text, got, tc.Lines)
		}
	}
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func TestPyIntText(t *testing.T) {
	for in, want := range map[string]string{
		"22": "22", " +22 ": "22", "-0": "0", "2_2": "22", "００７": "7", "007": "7", "-12": "-12",
		"99999999999999999999": "99999999999999999999",
	} {
		if got, ok := pyIntText(in); !ok || string(got) != want {
			t.Errorf("int(%q) = %s %v, want %s", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "_1", "1_", "1__2", "0x10", "1.0", "+", "2 2", "²"} {
		if _, ok := pyIntText(in); ok {
			t.Errorf("int(%q) accepted", in)
		}
	}
}

// The preview never reads more than the documented directives: every
// accepted, unblocked row names a valid host and a port in range, and no
// line can turn into a command or a route.
func FuzzPreviewOpenSSH(f *testing.F) {
	f.Add("Host web\n HostName web.test\n User deploy\n Port 22\n")
	f.Add("Host a b\n ProxyJump bastion\n IdentityFile ~/.ssh/k\nMatch all\n ProxyCommand nc %h %p\n")
	f.Add("Host \"q\\\"x\" 'y'#c\n HostName=h.test\r\n")
	f.Fuzz(func(t *testing.T, source string) {
		if !utf8.ValidString(source) || len(source) > exchangeMaxInputBytes {
			return
		}
		p, err := previewOpenSSH(source, nil)
		if err != nil {
			return
		}
		if len(p.rows) > exchangeMaxRecords {
			t.Fatalf("%d rows", len(p.rows))
		}
		for _, row := range p.rows {
			for _, m := range row.members {
				if !slices.Contains(exchangeFields, m.name) && m.name != "blocked" && m.name != "requires_jump" {
					t.Fatalf("unexpected member %q", m.name)
				}
			}
			if v, _ := row.get("blocked"); isTrue(v) {
				continue
			}
			port, _ := row.get("port")
			if n, ok := asInt(port); !ok || n < 1 || n > 65535 || !validHost(row.text("host")) || !exchangeAlias.MatchString(row.text("name")) {
				t.Fatalf("unblocked row %s", row.encode())
			}
		}
	})
}

func FuzzShlex(f *testing.F) {
	f.Add(`a "b c" 'd' e\ f # g`)
	f.Fuzz(func(t *testing.T, line string) {
		if strings.ContainsAny(line, "\n") || !utf8.ValidString(line) {
			return
		}
		tokens, err := shlexSplit(line)
		if err != nil {
			return
		}
		total := 0
		for _, tok := range tokens {
			total += len(tok)
		}
		if total > len(line) {
			t.Fatalf("tokens longer than the line: %q", tokens)
		}
	})
}

func importService(t *testing.T) (*Service, *ExchangeHTTP, *http.ServeMux) {
	t.Helper()
	h, mux := exchangeFixture(t)
	h.Service.Keys = fixedKeyOwner{"key-1": true}
	return h.Service, h, mux
}

type fixedKeyOwner map[string]bool

func (f fixedKeyOwner) HasKey(_ context.Context, _ int64, id string) (bool, error) { return f[id], nil }

func TestImportProfileRules(t *testing.T) {
	s, _, _ := importService(t)
	ctx := t.Context()
	base := protocol.HostsProfileSave{Name: v(`"Web"`), Host: v(`"web.test"`), Port: v(`22`), Username: v(`"deploy"`),
		AuthType: v(`"password"`), KeyID: v(`null`), JumpHostID: v(`null`), StartupMode: v(`"none"`)}
	first := s.ImportProfile(ctx, 3, base)
	if first.Err != nil || first.ID == "" || first.Duplicate {
		t.Fatalf("import: %+v", first)
	}
	// Same name in another case: skipped.
	again := base
	again.Name, again.Host = v(`"WEB"`), v(`"other.test"`)
	if out := s.ImportProfile(ctx, 3, again); !out.Duplicate {
		t.Fatalf("same name: %+v", out)
	}
	// Same endpoint under another name: skipped.
	endpoint := base
	endpoint.Name = v(`"Other name"`)
	if out := s.ImportProfile(ctx, 3, endpoint); !out.Duplicate {
		t.Fatalf("same endpoint: %+v", out)
	}
	// An id never updates a saved host.
	update := base
	update.ID, update.Name = jsonString(first.ID), v(`"Renamed"`)
	if out := s.ImportProfile(ctx, 3, update); out.Err == nil || fault.CodeOf(out.Err) == fault.NotFound {
		t.Fatalf("update through import: %+v", out)
	}
	// Mapped references must exist.
	keyed := base
	keyed.Name, keyed.Host, keyed.AuthType, keyed.KeyID = v(`"Keyed"`), v(`"k.test"`), v(`"key"`), v(`"key-9"`)
	if out := s.ImportProfile(ctx, 3, keyed); out.Err == nil {
		t.Fatalf("unknown key: %+v", out)
	}
	jumped := base
	jumped.Name, jumped.Host, jumped.JumpHostID = v(`"Jumped"`), v(`"j.test"`), v(`"jump-9"`)
	if out := s.ImportProfile(ctx, 3, jumped); out.Err == nil {
		t.Fatalf("unknown jump host: %+v", out)
	}
	jumped.JumpHostID = v(`"jump-1"`)
	if out := s.ImportProfile(ctx, 3, jumped); out.Err != nil || out.Duplicate {
		t.Fatalf("mapped jump host: %+v", out)
	}
	profiles, _ := s.Profiles(ctx, 3)
	if len(profiles) != 2 {
		t.Fatalf("%d profiles", len(profiles))
	}
}

// The whole flow through the routes: preview, import with mapping, a
// second import skips, the export round-trips into a preview.
func TestExchangeRoundTrip(t *testing.T) {
	_, _, mux := importService(t)
	source := "Host web\n HostName web.test\n User deploy\nHost keyed\n HostName k.test\n IdentityFile x\n User u\n"
	body := func(selections string) string {
		src, _ := json.Marshal(source)
		return `{"format":"openssh","source":` + string(src) + `,"selections":` + selections + `}`
	}
	rec := call(t, mux, "POST", "/api/profiles/exchange", body(`[{"index":0},{"index":1,"key_id":"key-1","username":"u"}]`))
	if rec.Code != 200 || strings.Count(rec.Body.String(), `"imported"`) != 2 {
		t.Fatalf("import: %d %s", rec.Code, rec.Body.String())
	}
	rec = call(t, mux, "POST", "/api/profiles/exchange", body(`[{"index":0}]`))
	if !strings.Contains(rec.Body.String(), `"skipped"`) {
		t.Fatalf("second import: %s", rec.Body.String())
	}
	rec = call(t, mux, "GET", "/api/profiles/exchange", "")
	if rec.Code != 200 || rec.Header().Get("X-WebSSH-SOCKS-Routes-Omitted") != "0" || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("export: %d %v", rec.Code, rec.Header())
	}
	exported, _ := json.Marshal(strings.TrimSpace(rec.Body.String()))
	rec = call(t, mux, "POST", "/api/profiles/exchange/preview", `{"format":"json","source":`+string(exported)+`}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"name":"keyed"`) || !strings.Contains(rec.Body.String(), `"requires_key":true`) {
		t.Fatalf("preview of the export: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "key-1") && !strings.Contains(rec.Body.String(), `"keys":[{"id":"key-1"`) {
		t.Fatalf("export leaked a key reference: %s", rec.Body.String())
	}
}

func TestExchangeExportArchive(t *testing.T) {
	s, _, mux := importService(t)
	var profiles []jsontext.Value
	for i := range 150 {
		profiles = append(profiles, v(`{"id":"p`+itoa(i)+`","name":"n`+itoa(i)+`","host":"h`+itoa(i)+`.test","port":22,"username":"u","auth_type":"password","key_id":null,"socks_proxy_id":"px","startup_mode":"none"}`))
	}
	legacy := Legacy{Profiles: profiles, SOCKSProxies: []jsontext.Value{v(`{"id":"px","name":"p","host":"p.test","port":1080,"username":"","auth_type":"none","remote_dns":true,"created_at":"x"}`)}}
	if err := s.DB.Write(t.Context(), func(tx *store.Tx) error {
		_, err := Import(t.Context(), tx, 4, legacy, DefaultLimits)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	ctxMux := mux
	rec := callAs(t, ctxMux, 4, "GET", "/api/profiles/exchange")
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/zip" || rec.Header().Get("X-WebSSH-SOCKS-Routes-Omitted") != "150" {
		t.Fatalf("archive: %d %v", rec.Code, rec.Header())
	}
	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil || len(zr.File) != 2 || zr.File[0].Name != "webssh-hosts-1.json" || zr.File[0].Method != zip.Store {
		t.Fatalf("archive entries: %v", err)
	}
	if strings.Contains(rec.Body.String(), `"px"`) {
		t.Fatal("export holds the SOCKS5 proxy reference")
	}
}

func itoa(i int) string { return string(jsonInt(int64(i))) }

func TestExchangeHTTPEdges(t *testing.T) {
	_, h, mux := importService(t)
	h.Limited = func(*http.Request, int64) bool { return true }
	if rec := call(t, mux, "POST", "/api/profiles/exchange/preview", `{"format":"openssh","source":""}`); rec.Code != 429 {
		t.Fatalf("rate limit: %d", rec.Code)
	}
	h.Limited = nil
	rec := httptestRequest(t, mux, "text/plain", `{"format":"openssh","source":""}`)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "Invalid import request.") {
		t.Fatalf("media type: %d %s", rec.Code, rec.Body.String())
	}
	big := `{"format":"openssh","source":"` + strings.Repeat("#", maxExchangeBody) + `"}`
	if rec := call(t, mux, "POST", "/api/profiles/exchange/preview", big); rec.Code != 400 {
		t.Fatalf("oversized body: %d", rec.Code)
	}
	if rec := callAnonymous(t, mux, "GET", "/api/profiles/exchange"); rec.Code != 401 {
		t.Fatalf("without a session: %d", rec.Code)
	}
}

func callAs(t *testing.T, mux *http.ServeMux, owner int64, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	ctx := principal.With(t.Context(), principal.Principal{UserID: owner, SessionID: "s", Username: "u"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequestWithContext(ctx, method, path, nil))
	return rec
}

func callAnonymous(t *testing.T, mux *http.ServeMux, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), method, path, nil))
	return rec
}

func httptestRequest(t *testing.T, mux *http.ServeMux, contentType, body string) *httptest.ResponseRecorder {
	t.Helper()
	ctx := principal.With(t.Context(), principal.Principal{UserID: 3, SessionID: "s", Username: "u"})
	req := httptest.NewRequestWithContext(ctx, "POST", "/api/profiles/exchange/preview", strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}
