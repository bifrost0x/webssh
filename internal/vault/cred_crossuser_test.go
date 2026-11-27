package vault

import (
	"context"
	"encoding/json/jsontext"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	json "encoding/json/v2"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
)

// RS8-H20: another user can neither rename, replace nor delete the
// owner's saved password through the HTTP routes: the review of the
// change answers 404, and so does the change with a review of its own.
func TestOtherUserCannotChangeACredential(t *testing.T) {
	t.Parallel()
	r, owner, id := seeded(t)
	before := r.state(t, owner).Credentials[0]
	h := &CredentialsHTTP{Service: r.svc, HTTPS: func(*http.Request) bool { return true }, Index: func(*http.Request) string { return "/" }}
	mux := http.NewServeMux()
	h.Register(mux)
	bob := principaltest.User(7)
	r.stores.set(7, Records{Profiles: []jsontext.Value{profileJSON("q1", "c.example")}, SMB: true})
	send := func(p principal.Principal, method, path, body string) (int, string) {
		req := httptest.NewRequest(method, path, strings.NewReader(body)).WithContext(principal.With(context.Background(), p))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	for _, c := range []struct{ method, mutation, body string }{
		{"PATCH", `{"method":"update","credential_id":"` + id + `","name":"Taken"}`, `"name":"Taken"`},
		{"PATCH", `{"method":"update","credential_id":"` + id + `","password":"bob"}`, `"password":"bob"`},
		{"DELETE", `{"method":"delete","credential_id":"` + id + `"}`, ``},
	} {
		code, out := send(bob, "POST", "/api/credentials/intents", `{"operation":"native","mutation":`+c.mutation+`}`)
		if code == http.StatusOK {
			var in struct {
				Intent string `json:"intent"`
			}
			if err := json.Unmarshal([]byte(out), &in); err != nil {
				t.Fatal(err)
			}
			body := `{"intent":"` + in.Intent + `"`
			if c.body != "" {
				body += "," + c.body
			}
			code, out = send(bob, c.method, "/api/credentials/"+id, body+"}")
		}
		if code != http.StatusNotFound {
			t.Errorf("%s %s: %d %s", c.method, c.mutation, code, out)
		}
	}
	after := r.state(t, owner).Credentials
	if len(after) != 1 || after[0].Name != before.Name || after[0].Version != before.Version {
		t.Fatalf("the owner's password changed: %+v", after)
	}
	if st := r.state(t, bob); len(st.Credentials) != 0 {
		t.Fatalf("another user sees the owner's password: %+v", st.Credentials)
	}
}
