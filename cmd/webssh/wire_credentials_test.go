package main

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"io"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/vault"
)

func enableCredentials(t *testing.T, sys *system) {
	t.Helper()
	err := sys.db.Write(t.Context(), func(tx *store.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO settings_app (key, value, source, updated_us) VALUES
			('credentials_enabled', 'true', 'admin', 0), ('credentials_enabled_revision', '"r1"', 'admin', 0)`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The wired vault reaches the saved hosts and jump hosts of internal/hosts
// and gives the terminal adapter the assigned password only for the
// unchanged target.
func TestCredentialsWiring(t *testing.T) {
	sys, ts := openTestSystem(t, nil)
	c := signUp(t, ts.URL, "admin1", "first-password-1")
	enableCredentials(t, sys)
	ctx := principal.With(t.Context(), principal.Principal{UserID: 1, SessionID: "s1"})
	j := func(s string) jsontext.Value { return jsontext.Value(s) }
	profile, err := sys.hosts.SaveProfile(ctx, 1, protocol.HostsProfileSave{Name: j(`"Box"`), Host: j(`"box.example"`),
		Port: j(`22`), Username: j(`"root"`), AuthType: j(`"password"`)})
	if err != nil {
		t.Fatal(err)
	}
	var rec struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(profile, &rec)
	apply := func(method string, payload map[string]any) error {
		mutation := map[string]any{"method": method}
		maps.Copy(mutation, payload)
		body, _ := json.Marshal(map[string]any{"operation": "native", "mutation": mutation})
		out, err := sys.vault.Prepare(ctx, body)
		if err != nil {
			return err
		}
		var in struct {
			Intent string `json:"intent"`
		}
		_ = json.Unmarshal(out, &in)
		payload["intent"] = in.Intent
		body, _ = json.Marshal(payload)
		_, err = sys.vault.Apply(ctx, method, "", body, "")
		return err
	}
	if err := apply(vault.MethodCreate, map[string]any{"resource_id": rec.ID, "name": "Box", "password": "box-secret", "confirm_target": true}); err != nil {
		t.Fatal(err)
	}
	saved := savedPasswords{sys.vault}
	if pw, err := saved.Password(t.Context(), 1, rec.ID); err != nil || pw != "box-secret" {
		t.Fatalf("saved password: %q %v", pw, err)
	}
	if _, err := saved.Password(t.Context(), 1, "jump:none"); fault.CodeOf(err) != fault.CredentialMissing {
		t.Errorf("unknown resource: %v", err)
	}
	if _, err := sys.hosts.SaveProfile(ctx, 1, protocol.HostsProfileSave{ID: j(`"` + rec.ID + `"`), Name: j(`"Box"`),
		Host: j(`"elsewhere.example"`), Port: j(`22`), Username: j(`"root"`), AuthType: j(`"password"`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := saved.Password(t.Context(), 1, rec.ID); fault.CodeOf(err) != fault.CredentialTargetChanged {
		t.Errorf("moved host: %v", err)
	}
	// create_for_resource through the hosts adapter.
	if err := apply(vault.MethodCreateForResource, map[string]any{"resource_kind": "jump", "confirm_target": true, "name": "J", "password": "jump-secret",
		"resource": map[string]any{"name": "Jump", "host": "jump.example", "port": 22, "username": "u", "auth_type": "password"}}); err != nil {
		t.Fatal(err)
	}
	jumps, err := sys.hosts.JumpHosts(t.Context(), 1)
	if err != nil || len(jumps) != 1 {
		t.Fatalf("jump hosts %v %v", jumps, err)
	}
	var jr struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(jumps[0], &jr)
	if pw, err := saved.Password(t.Context(), 1, "jump:"+jr.ID); err != nil || pw != "jump-secret" {
		t.Fatalf("jump password: %q %v", pw, err)
	}
	// HTTP needs HTTPS: the browser's Origin states it behind a proxy.
	u, _ := url.Parse(ts.URL)
	for origin, want := range map[string]int{"": http.StatusForbidden, "https://" + u.Host: http.StatusOK} {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+"/api/credentials/state", nil)
		req.Header.Set("Accept", "application/json")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != want || (want == http.StatusOK && !strings.Contains(string(raw), `"credential_status":"changed"`)) {
			t.Errorf("origin %q: %d %s", origin, resp.StatusCode, raw)
		}
	}
}
