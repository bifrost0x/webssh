package httpapi

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// The transfer upload streams its body: the edge neither buffers nor
// bounds it, but the session, the origin and the CSRF header still apply.
func TestStreamRouteKeepsChecksWithoutBuffering(t *testing.T) {
	e := newEdge(t)
	const target = "/api/transfers/" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + "/upload"
	e.h.Mux().HandleFunc("POST /api/transfers/{token}/upload", func(w http.ResponseWriter, r *http.Request) {
		if _, buffered := r.Body.(readCloser); buffered {
			t.Error("the edge buffered a streamed body")
		}
		echo(w, r)
	})
	binding, token := e.csrf(alice.SessionID)
	big := strings.Repeat("x", 3*controlRequestLimit)
	w := e.do(req{method: http.MethodPost, target: target, body: big, token: "tok-alice", binding: binding,
		headers: map[string]string{"X-CSRFToken": token, "Content-Type": "application/octet-stream"}})
	if w.Code != http.StatusOK || w.Header().Get("X-Body-Len") != strconv.Itoa(len(big)) || w.Header().Get("X-User") != "1" {
		t.Fatalf("upload: %d %s", w.Code, w.Body)
	}
	form := url.Values{"csrf_token": {token}}.Encode()
	for name, rq := range map[string]req{
		"no session":   {method: http.MethodPost, target: target, body: big, binding: binding, headers: map[string]string{"X-CSRFToken": token}},
		"no token":     {method: http.MethodPost, target: target, body: big, token: "tok-alice", binding: binding},
		"form token":   {method: http.MethodPost, target: target, body: form, token: "tok-alice", binding: binding, headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}},
		"recovery":     {method: http.MethodPost, target: target, body: "x", token: "tok-repair", binding: binding, headers: map[string]string{"X-CSRFToken": e.h.csrfToken(binding, repair.SessionID)}},
		"cross origin": {method: http.MethodPost, target: target, body: "x", token: "tok-alice", binding: binding, headers: map[string]string{"X-CSRFToken": token, "Origin": "https://evil.example"}},
	} {
		if w := e.do(rq); w.Code == http.StatusOK {
			t.Errorf("%s: accepted", name)
		}
	}
	if AccessUserStream.String() != "user-stream" {
		t.Fatal(AccessUserStream.String())
	}
}
