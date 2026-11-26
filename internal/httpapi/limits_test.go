package httpapi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBodyLimits(t *testing.T) {
	e := newEdge(t)
	mux := e.h.Mux()
	mux.HandleFunc("POST /api/account/preferences", echo)
	mux.HandleFunc("POST /api/totp/enroll", echo)
	mux.HandleFunc("POST /api/webauthn/register/options", echo)
	binding, token := e.csrf(alice.SessionID)
	cases := []struct {
		path string
		size int
		want int
	}{
		{"/api/account/preferences", 64 << 10, 200},
		{"/api/account/preferences", 64<<10 + 1, 413},
		{"/api/totp/enroll", 16 << 10, 200},
		{"/api/totp/enroll", 16<<10 + 1, 413},
		{"/api/webauthn/register/options", 32<<10 + 1, 413},
		{"/api/webauthn/register/options", 32 << 10, 200},
	}
	for _, c := range cases {
		w := e.do(req{method: http.MethodPost, target: c.path, body: strings.Repeat("a", c.size), token: "tok-alice", binding: binding,
			headers: map[string]string{"X-CSRFToken": token}})
		if w.Code != c.want {
			t.Errorf("%s with %d bytes: %d, want %d", c.path, c.size, w.Code, c.want)
		}
		if c.want == 413 && strings.TrimSpace(w.Body.String()) != `{"success":false,"code":"too_large","error":"Request body too large"}` {
			t.Errorf("413 body %s", w.Body)
		}
	}
}

// A body without Content-Length is bounded while it is read.
func TestChunkedBodyIsBounded(t *testing.T) {
	e := newEdge(t)
	called := false
	e.h.Mux().HandleFunc("POST /api/account/preferences", func(http.ResponseWriter, *http.Request) { called = true })
	binding, token := e.csrf(alice.SessionID)
	r := httptest.NewRequest(http.MethodPost, "http://webssh.test/api/account/preferences", io.MultiReader(strings.NewReader(strings.Repeat("a", 70<<10))))
	r.ContentLength = -1
	r.AddCookie(&http.Cookie{Name: "session", Value: "tok-alice"})
	r.AddCookie(&http.Cookie{Name: "session_binding", Value: binding})
	r.Header.Set("X-CSRFToken", token)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge || called {
		t.Fatalf("%d, handler called %v", w.Code, called)
	}
}

// The limit applies before the session lookup and the CSRF check.
func TestTooLargeBeforeCSRF(t *testing.T) {
	e := newEdge(t)
	w := e.do(req{method: http.MethodPost, target: "/login", body: strings.Repeat("a", 65<<10)})
	if w.Code != http.StatusRequestEntityTooLarge || e.sessions.calls.Load() != 0 {
		t.Fatalf("%d, lookups %d", w.Code, e.sessions.calls.Load())
	}
}

// Requests get read and write deadlines on the connection; the realtime
// endpoint does not.
func TestDeadlines(t *testing.T) {
	e := newEdge(t)
	e.h.Mux().HandleFunc("GET /login", echo)
	e.h.Mux().HandleFunc("GET /ws", echo)
	srv := httptest.NewUnstartedServer(e.h)
	ConfigureServer(srv.Config)
	srv.Start()
	defer srv.Close()
	for _, path := range []string{"/login", "/ws"} {
		resp, err := srv.Client().Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d", path, resp.StatusCode)
		}
	}
	if strings.Contains(e.logs.String(), "deadline not set") || requestReadTimeout <= 0 || requestWriteTimeout < time.Minute {
		t.Fatalf("deadlines are not set:\n%s", e.logs)
	}
}

// The realtime endpoint takes the connection over through the edge's
// response writer.
func TestUpgradeCanHijack(t *testing.T) {
	e := newEdge(t)
	e.h.Mux().HandleFunc("GET /ws", func(w http.ResponseWriter, r *http.Request) {
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()
		_, _ = brw.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nraw-ok")
		_ = brw.Flush()
	})
	// httptest.Server.Close does not wait for hijacked connections, so
	// the test waits for the edge itself to return; it logs before that.
	served := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(served)
		e.h.ServeHTTP(w, r)
	}))
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL + "/ws")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "raw-ok" {
		t.Fatalf("body %q", body)
	}
	select {
	case <-served:
	case <-time.After(10 * time.Second):
		t.Fatal("edge handler did not return")
	}
	if !strings.Contains(e.logs.String(), "status=101") {
		t.Fatalf("hijacked request not logged as upgrade:\n%s", e.logs)
	}
}
