package hostops

import (
	"context"
	json "encoding/json/v2"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
)

type fakeInventory map[int64]OverviewInventory

func (f fakeInventory) OverviewInventory(_ context.Context, owner int64) (OverviewInventory, error) {
	return f[owner], nil
}

type fakeTrust struct {
	trusted map[string]bool
	calls   []string
	err     error
}

func (f *fakeTrust) Trusted(_ context.Context, owner int64, host string, port int) (bool, error) {
	key := host + ":" + string(rune('0'+owner)) + ":" + itoa(port)
	f.calls = append(f.calls, key)
	return f.trusted[host+":"+itoa(port)], f.err
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func TestReadinessRules(t *testing.T) {
	inv := OverviewInventory{
		Hosts: []OverviewHost{
			{ID: "ready", Host: "a", Port: 22, AuthType: "key", KeyID: "k1"},
			{ID: "default-port", Host: "a", AuthType: "password"},
			{ID: "untrusted", Host: "b", Port: 22, AuthType: "password"},
			{ID: "key-missing", Host: "a", Port: 22, AuthType: "key", KeyID: "gone"},
			{ID: "jump", Host: "a", Port: 22, JumpHostID: "j1", AuthType: "password"},
			{ID: "jump-missing", Host: "a", Port: 22, JumpHostID: "gone", AuthType: "password"},
			{ID: "socks-open", Host: "a", Port: 22, SOCKSProxyID: "s-none", AuthType: "password"},
			{ID: "socks-login", Host: "a", Port: 22, SOCKSProxyID: "s-pass", AuthType: "password"},
			{ID: "socks-missing", Host: "a", Port: 22, SOCKSProxyID: "gone", AuthType: "password"},
			{ID: "socks-and-jump", Host: "a", Port: 22, SOCKSProxyID: "s-none", JumpHostID: "j1", AuthType: "password"},
			{ID: "socks-tailscale", Host: "a", Port: 22, SOCKSProxyID: "s-none", AuthType: "tailscale"},
			{ID: "tailscale", Host: "a", Port: 22, AuthType: "tailscale"},
		},
		JumpHostIDs:  []string{"j1"},
		KeyIDs:       []string{"k1"},
		SOCKSProxies: map[string]string{"s-none": "none", "s-pass": "password"},
	}
	trust := &fakeTrust{trusted: map[string]bool{"a:22": true}}
	rows, err := readiness(t.Context(), 1, inv, trust)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range rows {
		b, _ := json.Marshal(r)
		got[r.ID] = string(b)
	}
	want := map[string]string{
		"ready":           `{"id":"ready","state":"ready","route":"direct","host_key":"trusted","auth":"ready"}`,
		"default-port":    `{"id":"default-port","state":"ready","route":"direct","host_key":"trusted","auth":"prompt"}`,
		"untrusted":       `{"id":"untrusted","state":"action","route":"direct","host_key":"unknown","auth":"prompt"}`,
		"key-missing":     `{"id":"key-missing","state":"action","route":"direct","host_key":"trusted","auth":"key_missing"}`,
		"jump":            `{"id":"jump","state":"ready","route":"jump","host_key":"trusted","auth":"prompt"}`,
		"jump-missing":    `{"id":"jump-missing","state":"broken","route":"missing","host_key":"trusted","auth":"prompt"}`,
		"socks-open":      `{"id":"socks-open","state":"ready","route":"socks","host_key":"trusted","auth":"prompt","socks_proxy_id":"s-none","via_socks":true,"socks_auth":"ready"}`,
		"socks-login":     `{"id":"socks-login","state":"action","route":"socks","host_key":"trusted","auth":"prompt","socks_proxy_id":"s-pass","via_socks":true,"socks_auth":"password_required"}`,
		"socks-missing":   `{"id":"socks-missing","state":"broken","route":"missing","host_key":"trusted","auth":"prompt","socks_proxy_id":"gone","via_socks":true}`,
		"socks-and-jump":  `{"id":"socks-and-jump","state":"broken","route":"missing","host_key":"trusted","auth":"prompt","socks_proxy_id":"s-none","via_socks":true,"socks_auth":"ready"}`,
		"socks-tailscale": `{"id":"socks-tailscale","state":"broken","route":"missing","host_key":"trusted","auth":"prompt","socks_proxy_id":"s-none","via_socks":true,"socks_auth":"ready"}`,
		"tailscale":       `{"id":"tailscale","state":"ready","route":"direct","host_key":"trusted","auth":"prompt"}`,
	}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("%s:\n got %s\nwant %s", id, got[id], w)
		}
	}
	if len(rows) != len(inv.Hosts) || rows[0].ID != "ready" {
		t.Error("rows follow the saved order")
	}
	if !strings.HasSuffix(trust.calls[1], ":22") {
		t.Errorf("default port: %v", trust.calls[1])
	}
}

func TestOverviewHTTP(t *testing.T) {
	trust := &fakeTrust{trusted: map[string]bool{}}
	h := &OverviewHTTP{
		Inventory: fakeInventory{1: {Hosts: []OverviewHost{{ID: "p1", Host: "a", AuthType: "password"}}},
			2: {Hosts: []OverviewHost{{ID: "p2", Host: "b", AuthType: "password"}}}},
		Trust:  trust,
		Logger: slog.New(slog.DiscardHandler),
		now:    func() time.Time { return time.Unix(1700000000, 250000000) },
	}
	mux := http.NewServeMux()
	h.Register(mux)
	get := func(p *principal.Principal, path string) (int, string, http.Header) {
		r := httptest.NewRequest("GET", path, nil)
		if p != nil {
			r = r.WithContext(principal.With(r.Context(), *p))
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w.Code, w.Body.String(), w.Header()
	}
	u := principaltest.User(1)
	code, body, hdr := get(&u, "/api/overview/status")
	const want = `{"hosts":[{"id":"p1","state":"action","route":"direct","host_key":"unknown","auth":"prompt"}],` +
		`"generated_at":1700000000.25,"available":{"automation":true,"reachability":false,"readiness":true}}`
	if code != 200 || body != want || hdr.Get("Cache-Control") != "no-store" {
		t.Errorf("%d %s", code, body)
	}
	// Only the account's own hosts.
	if strings.Contains(body, "p2") {
		t.Error("another account's host")
	}
	if code, body, _ := get(&u, "/api/overview/reachability"); code != 200 || body != `{"available":false,"results":null}` {
		t.Errorf("reachability %d %s", code, body)
	}
	if code, _, _ := get(nil, "/api/overview/status"); code != 401 {
		t.Errorf("without principal %d", code)
	}
	rec := principaltest.User(1)
	rec.Recovery = true
	if code, _, _ := get(&rec, "/api/overview/reachability"); code != 403 {
		t.Errorf("recovery session %d", code)
	}
	trust.err = errors.New("disk")
	if code, body, _ := get(&u, "/api/overview/status"); code != 500 || strings.Contains(body, "disk") {
		t.Errorf("internal error leaks or passes: %d %s", code, body)
	}
	trust.err = fault.New(fault.StorageError, "")
	if code, _, _ := get(&u, "/api/overview/status"); code != 500 {
		t.Errorf("storage error %d", code)
	}
}
