package hosts

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/principal"
)

func TestPresetsHTTP(t *testing.T) {
	s := seeded(t, Legacy{})
	mux := http.NewServeMux()
	(&HTTP{Service: s}).Register(mux)
	call := func(method, body, contentType string, signedIn bool) *httptest.ResponseRecorder {
		r := httptest.NewRequestWithContext(t.Context(), method, "/api/account/workspace-presets", strings.NewReader(body))
		if contentType != "" {
			r.Header.Set("Content-Type", contentType)
		}
		if signedIn {
			r = r.WithContext(principal.With(r.Context(), principal.Principal{UserID: oracleUser, SessionID: "s"}))
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	if w := call("GET", "", "", false); w.Code != http.StatusUnauthorized {
		t.Fatalf("signed out: %d", w.Code)
	}
	if w := call("GET", "", "", true); w.Code != 200 || w.Body.String() != `{"presets":[]}` || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("empty list: %d %s", w.Code, w.Body)
	}
	body := `{"presets":[{"id":"p1","name":"One","layout":1,"profile_ids":["syn-free"]}]}`
	if w := call("PUT", body, "application/json", true); w.Code != 200 || w.Body.String() != body {
		t.Fatalf("save: %d %s", w.Code, w.Body)
	}
	for name, c := range map[string]struct{ body, contentType string }{
		"form body":        {body, "application/x-www-form-urlencoded"},
		"extra member":     {`{"presets":[],"x":1}`, "application/json"},
		"duplicate member": {`{"presets":[],"presets":[]}`, "application/json"},
		"missing presets":  {`{}`, "application/json"},
		"not json":         {`presets`, "application/json"},
		"foreign host":     {`{"presets":[{"id":"p1","name":"One","layout":1,"profile_ids":["nope"]}]}`, "application/json"},
	} {
		if w := call("PUT", c.body, c.contentType, true); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"success":false`) {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	if w := call("PUT", `{"presets":"`+strings.Repeat("x", maxPresetBody)+`"}`, "application/json", true); w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body: %d", w.Code)
	}
	if w := call("GET", "", "", true); w.Body.String() != body {
		t.Fatalf("refused writes changed the presets: %s", w.Body)
	}
}
