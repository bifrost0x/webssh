package httpapi

import (
	"encoding/json/v2"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

type pythonRoute struct {
	Method string `json:"method"`
	Rule   string `json:"rule"`
}

var flaskConverter = regexp.MustCompile(`<(?:(path):)?(?:\w+:)?(\w+)>`)

// flaskPattern turns a Flask rule into a ServeMux pattern.
func flaskPattern(method, rule string) string {
	path := flaskConverter.ReplaceAllStringFunc(rule, func(m string) string {
		sub := flaskConverter.FindStringSubmatch(m)
		if sub[1] == "path" {
			return "{" + sub[2] + "...}"
		}
		return "{" + sub[2] + "}"
	})
	if path == "/" {
		path = "/{$}"
	}
	return method + " " + path
}

func loadPythonRoutes(t *testing.T) []pythonRoute {
	t.Helper()
	data, err := os.ReadFile("testdata/python-routes.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Routes []pythonRoute `json:"routes"`
	}
	if err := json.Unmarshal(data, &doc, json.RejectUnknownMembers(false)); err != nil {
		t.Fatal(err)
	}
	if len(doc.Routes) < 150 {
		t.Fatalf("only %d Python routes; the fixture is incomplete", len(doc.Routes))
	}
	return doc.Routes
}

// goOnlyRoutes are catalog routes without a Python counterpart.
// The handoff of large editor and image answers (internal/files) keeps
// them out of the realtime queue.
var goOnlyRoutes = []string{"GET /ws", "GET /api/realtime/status", "GET /api/files/handoff/{}"}

// TestRouteCatalogCoversPython: every route of the Python release is a
// route of the catalog or dropped by a decision, never both, and the
// catalog holds nothing else.
func TestRouteCatalogCoversPython(t *testing.T) {
	built := map[string]Access{}
	for _, rt := range catalogRoutes() {
		if _, dup := built[patternKey(rt.pattern)]; dup {
			t.Errorf("the catalog lists %q twice", rt.pattern)
		}
		built[patternKey(rt.pattern)] = rt.access
	}
	dropped := map[string]bool{}
	for p, decision := range droppedRoutes {
		k := patternKey(p)
		if !strings.HasPrefix(decision, "D-") {
			t.Errorf("dropped route %q names no decision", p)
		}
		if _, both := built[k]; both {
			t.Errorf("%q is both dropped and in the catalog", p)
		}
		dropped[k] = true
	}
	seen := map[string]bool{}
	for _, r := range loadPythonRoutes(t) {
		k := patternKey(flaskPattern(r.Method, r.Rule))
		seen[k] = true
		if _, ok := built[k]; !ok && !dropped[k] {
			t.Errorf("Python route %s %s is neither built nor dropped", r.Method, r.Rule)
		}
	}
	for k := range built {
		if !seen[k] && !slices.Contains(goOnlyRoutes, k) {
			t.Errorf("the catalog has %q, which the Python release does not have", k)
		}
	}
	for k := range dropped {
		if !seen[k] {
			t.Errorf("droppedRoutes has %q, which the Python release does not have", k)
		}
	}
}

// A catalog route nobody registered answers 404 like an unknown route,
// and Finish names it, so that the composition root can refuse to start.
// No route answers not_available_in_preview.
func TestEveryCatalogRouteIsAnsweredWithoutHandlers(t *testing.T) {
	e := newEdge(t)
	filled, err := e.h.Finish()
	if err != nil {
		t.Fatal(err)
	}
	// Only the edge's own routes have handlers in a bare edge.
	own := []string{"GET /health", "GET /ready", "GET /static/{path...}", "GET /api/realtime/status"}
	if want := len(catalogRoutes()) - len(own); len(filled) != want {
		t.Fatalf("Finish filled %d routes, want %d: %v", len(filled), want, filled)
	}
	if again, _ := e.h.Finish(); len(again) != len(filled) {
		t.Fatalf("a second Finish reports %d routes, want %d", len(again), len(filled))
	}
	for _, rt := range catalogRoutes() {
		if slices.Contains(own, rt.pattern) {
			continue
		}
		method, path := samplePath(rt.pattern)
		binding, token := e.csrf("s-root")
		w := e.do(req{method: method, target: path, token: "tok-root", binding: binding,
			headers: map[string]string{"X-CSRFToken": token, "Accept": "application/json"}})
		if rt.access == AccessUpgrade {
			if w.Code != http.StatusNotFound {
				t.Errorf("%s: status %d, want 404", rt.pattern, w.Code)
			}
			continue
		}
		if w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), "preview") {
			t.Errorf("%s: %d %s, want 404", rt.pattern, w.Code, w.Body)
		}
	}
}

// The dropped routes answer 404 like any route the server does not have.
func TestDroppedRoutesAreNotFound(t *testing.T) {
	e := newEdge(t)
	for p := range droppedRoutes {
		method, path := samplePath(p)
		binding, token := e.csrf("s-root")
		w := e.do(req{method: method, target: path, token: "tok-root", binding: binding,
			headers: map[string]string{"X-CSRFToken": token, "Accept": "application/json"}})
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", p, w.Code)
		}
	}
}

func TestRegisteredRouteIsNotFilled(t *testing.T) {
	e := newEdge(t)
	e.h.Mux().HandleFunc("GET /api/host-keys/{entry}/deletion-impact", echo)
	filled, err := e.h.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(filled, "GET /api/host-keys/{id}/deletion-impact") {
		t.Fatal("a registered route with another wildcard name was filled")
	}
	w := e.do(req{target: "/api/host-keys/7/deletion-impact", token: "tok-alice"})
	if w.Code != http.StatusOK || w.Header().Get("X-User") != "1" {
		t.Fatalf("got %d user %q", w.Code, w.Header().Get("X-User"))
	}
}

func TestRouteOutsideCatalogIsRefused(t *testing.T) {
	e := newEdge(t)
	e.h.Mux().HandleFunc("GET /api/unlisted", echo)
	w := e.do(req{target: "/api/unlisted", token: "tok-root"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404 for a route outside the catalog", w.Code)
	}
	if !strings.Contains(e.logs.String(), "not in the catalog") {
		t.Fatal("refusal not logged")
	}
}

func TestPatternKeyAndSamplePath(t *testing.T) {
	cases := map[string]string{
		"GET /a/{id}/b":       "GET /a/{}/b",
		"GET /static/{p...}":  "GET /static/{...}",
		"GET /{$}":            "GET /{$}",
		"DELETE /x/{a}/y/{b}": "DELETE /x/{}/y/{}",
	}
	for in, want := range cases {
		if got := patternKey(in); got != want {
			t.Errorf("patternKey(%q) = %q, want %q", in, got, want)
		}
	}
	if m, p := samplePath("GET /{$}"); m != "GET" || p != "/" {
		t.Errorf("samplePath root = %q %q", m, p)
	}
	if _, p := samplePath("GET /static/{path...}"); p != "/static/x" {
		t.Errorf("samplePath wildcard = %q", p)
	}
}

func TestAdminGated(t *testing.T) {
	for path, want := range map[string]bool{
		"/admin": true, "/admin/": true, "/admin/api/users": true, "/api/step-up/password": true,
		"/administrator": false, "/api/account/step-up/password": false, "/": false,
	} {
		if adminGated(path) != want {
			t.Errorf("adminGated(%q) = %v", path, !want)
		}
	}
}
