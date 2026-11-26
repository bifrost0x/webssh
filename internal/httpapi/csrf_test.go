package httpapi

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/config"
)

func csrfEdge(t *testing.T, opts ...edgeOption) *edge {
	e := newEdge(t, opts...)
	e.h.Mux().HandleFunc("POST /api/account/preferences", echo)
	e.h.Mux().HandleFunc("POST /login", echo)
	return e
}

func TestCSRFRefusals(t *testing.T) {
	e := csrfEdge(t)
	binding, token := e.csrf(alice.SessionID)
	_, otherBrowserToken := e.csrf(alice.SessionID)
	otherSessionToken := e.h.csrfToken(binding, aliceTwo.SessionID)
	anonymousToken := e.h.csrfToken(binding, "")
	cases := []struct {
		name    string
		binding string
		header  string
	}{
		{"no token", binding, ""},
		{"wrong token", binding, "AAAA" + token[4:]},
		{"token of another browser", binding, otherBrowserToken},
		{"token of another session", binding, otherSessionToken},
		{"token from before sign-in", binding, anonymousToken},
		{"no binding cookie", "", token},
		{"malformed binding cookie", "short", token},
		{"oversized token", binding, strings.Repeat("A", 300)},
	}
	for _, c := range cases {
		headers := map[string]string{"Content-Type": "application/json"}
		if c.header != "" {
			headers["X-CSRFToken"] = c.header
		}
		w := e.do(req{method: http.MethodPost, target: "/api/account/preferences", body: "{}", token: "tok-alice", binding: c.binding, headers: headers})
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"code":"csrf_expired"`) {
			t.Errorf("%s: %d %s", c.name, w.Code, w.Body)
		}
	}
}

func TestCSRFAccepted(t *testing.T) {
	e := csrfEdge(t)
	binding, token := e.csrf(alice.SessionID)
	for _, header := range []string{"X-CSRFToken", "X-CSRF-Token"} {
		w := e.do(req{method: http.MethodPost, target: "/api/account/preferences", body: `{"theme":"x"}`, token: "tok-alice", binding: binding,
			headers: map[string]string{header: token, "Content-Type": "application/json"}})
		if w.Code != http.StatusOK || w.Header().Get("X-Body-Len") != "13" {
			t.Errorf("%s: %d %s (body %s)", header, w.Code, w.Body, w.Header().Get("X-Body-Len"))
		}
	}
	// The sign-in form sends the field; before sign-in the token binds to
	// the browser only.
	binding, token = e.csrf("")
	form := url.Values{"csrf_token": {token}, "username": {"alice"}}.Encode()
	w := e.do(req{method: http.MethodPost, target: "/login", body: form, binding: binding,
		headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}})
	if w.Code != http.StatusOK || w.Header().Get("X-Body-Len") != strconv.Itoa(len(form)) {
		t.Fatalf("form: %d %s", w.Code, w.Body)
	}
}

func TestCSRFTokenIsPublishedAndBindingSet(t *testing.T) {
	e := newEdge(t, withConfig(func(c *config.Config) {
		c.ApplicationRoot = "/webssh"
		c.Cookies.Secure = true
	}))
	var seen, bound string
	e.h.Mux().HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		seen, bound = CSRFToken(r), BrowserBinding(r)
	})
	w := e.do(req{target: "/login"})
	var binding *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "session_binding" {
			binding = c
		}
	}
	if binding == nil || !binding.HttpOnly || !binding.Secure || binding.SameSite != http.SameSiteLaxMode || binding.Path != "/webssh" {
		t.Fatalf("binding cookie %+v", binding)
	}
	if bound != binding.Value || seen != e.h.csrfToken(binding.Value, "") {
		t.Fatal("the published token does not belong to the binding")
	}
	// An existing binding is kept.
	w = e.do(req{target: "/login", binding: binding.Value})
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("a valid binding cookie was replaced")
	}
	// Probes and static files do not get one.
	if len(e.do(req{target: "/health"}).Result().Cookies()) != 0 {
		t.Fatal("/health sets a cookie")
	}
}

func TestFormCSRFFailureShowsPage(t *testing.T) {
	e := csrfEdge(t)
	e.h.renderer = testRenderer(t)
	binding, _ := e.csrf("")
	w := e.do(req{method: http.MethodPost, target: "/login", body: "csrf_token=bad", binding: binding,
		headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `data-i18n="auth.formExpired"`) || !strings.Contains(w.Body.String(), `href="/login"`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestSecureCookieOverHTTPIsExplained(t *testing.T) {
	e := csrfEdge(t, withConfig(func(c *config.Config) { c.Cookies.Secure = true }))
	e.h.renderer = testRenderer(t)
	w := e.do(req{method: http.MethodPost, target: "/login", body: "csrf_token=x",
		headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "errors.cookieRejectedTitle") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	// Over HTTPS (page origin https on this host) it is the ordinary page.
	w = e.do(req{method: http.MethodPost, target: "/login", body: "csrf_token=x",
		headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Origin": "https://webssh.test"}})
	if strings.Contains(w.Body.String(), "errors.cookieRejectedTitle") {
		t.Fatal("cookie_rejected for a page served over HTTPS")
	}
}

func TestCrossOriginRequestsAreRefused(t *testing.T) {
	e := csrfEdge(t)
	binding, token := e.csrf(alice.SessionID)
	cases := []struct {
		name    string
		headers map[string]string
		want    int
	}{
		{"cross-site fetch", map[string]string{"Sec-Fetch-Site": "cross-site"}, 403},
		{"same-site fetch", map[string]string{"Sec-Fetch-Site": "same-site"}, 403},
		{"foreign origin", map[string]string{"Origin": "https://evil.test"}, 403},
		{"null origin", map[string]string{"Origin": "null"}, 403},
		{"foreign referer", map[string]string{"Referer": "https://evil.test/page"}, 403},
		{"same-origin fetch", map[string]string{"Sec-Fetch-Site": "same-origin"}, 200},
		{"own origin", map[string]string{"Origin": "http://webssh.test"}, 200},
		{"own referer", map[string]string{"Referer": "http://webssh.test/settings"}, 200},
		{"no browser headers", map[string]string{}, 200},
	}
	for _, c := range cases {
		c.headers["X-CSRFToken"] = token
		w := e.do(req{method: http.MethodPost, target: "/api/account/preferences", token: "tok-alice", binding: binding, headers: c.headers})
		if w.Code != c.want {
			t.Errorf("%s: %d, want %d (%s)", c.name, w.Code, c.want, w.Body)
		}
	}
}

func TestOriginComparesTheForwardedHost(t *testing.T) {
	e := csrfEdge(t, withConfig(func(c *config.Config) { c.Proxies.Hops = 1 }))
	binding, token := e.csrf(alice.SessionID)
	headers := map[string]string{"X-CSRFToken": token, "Origin": "https://ssh.example.com",
		"X-Forwarded-For": "192.0.2.9", "X-Forwarded-Host": "ssh.example.com", "X-Forwarded-Proto": "https"}
	w := e.do(req{method: http.MethodPost, target: "/api/account/preferences", token: "tok-alice", binding: binding, headers: headers})
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func FuzzCSRFCheck(f *testing.F) {
	e := newEdge(f)
	f.Add("csrf_token=abc", "application/x-www-form-urlencoded", "abc")
	f.Add("%zz", "application/x-www-form-urlencoded", "")
	f.Fuzz(func(t *testing.T, body, ctype, header string) {
		r, _ := http.NewRequest(http.MethodPost, "http://webssh.test/login", strings.NewReader(body))
		r.Header.Set("Content-Type", ctype)
		r.Header.Set("X-CSRFToken", header)
		binding := newBinding()
		r = r.WithContext(e.h.csrfBegin(nopWriter{}, withBinding(r, binding), ""))
		if e.h.csrfCheck(r, []byte(body)) == nil {
			t.Fatalf("accepted a token that is not the binding's: %q %q", body, header)
		}
	})
}

func withBinding(r *http.Request, binding string) *http.Request {
	r.AddCookie(&http.Cookie{Name: "session_binding", Value: binding})
	return r
}

type nopWriter struct{}

func (nopWriter) Header() http.Header         { return http.Header{} }
func (nopWriter) Write(b []byte) (int, error) { return len(b), nil }
func (nopWriter) WriteHeader(int)             {}
