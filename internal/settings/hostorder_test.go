package settings

import (
	"encoding/json/jsontext"
	"slices"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
)

// The overview keeps the order of its host cards per account in the
// overview preferences, next to the panel arrangement. The member is
// optional: without it the page keeps its default order.

func TestOverviewHostOrderIsStoredPerAccount(t *testing.T) {
	h, mux := newHTTP(t)
	u := principaltest.User(2)
	other := principaltest.User(3)
	r := call(t, mux, &u, "PUT", "/api/overview/preferences", `{"host_order":["web","db-1","nas"]}`, "application/json")
	if r.status != 200 || r.raw != `{"dismissed":[],"host_order":["web","db-1","nas"],"panels":null}` {
		t.Fatalf("store: %d %s", r.status, r.raw)
	}
	// A new read of the store, as after a reload of the page.
	got, err := h.Settings.User(t.Context(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.OverviewHostOrder, []string{"web", "db-1", "nas"}) {
		t.Errorf("stored %v", got.OverviewHostOrder)
	}
	if o, err := h.Settings.User(t.Context(), 3); err != nil || o.OverviewHostOrder != nil {
		t.Errorf("another account has an order: %v %v", o.OverviewHostOrder, err)
	}
	// Panels and acknowledgements keep their values.
	r = call(t, mux, &u, "PUT", "/api/overview/preferences", `{"panels":[{"id":"hosts","w":6}],"dismissed":["reboot:a"]}`, "application/json")
	if r.raw != `{"dismissed":["reboot:a"],"host_order":["web","db-1","nas"],"panels":[{"id":"hosts","w":6}]}` {
		t.Errorf("other members: %s", r.raw)
	}
	// null restores the default order and the answer is the one of an
	// account that never arranged its hosts.
	r = call(t, mux, &u, "PUT", "/api/overview/preferences", `{"host_order":null}`, "application/json")
	if r.status != 200 || r.raw != `{"dismissed":["reboot:a"],"panels":[{"id":"hosts","w":6}]}` {
		t.Errorf("reset: %d %s", r.status, r.raw)
	}
	if got, _ := h.Settings.User(t.Context(), 2); got.OverviewHostOrder != nil {
		t.Errorf("after reset %v", got.OverviewHostOrder)
	}
	if r := call(t, mux, &other, "PUT", "/api/overview/preferences", `{"host_order":[]}`, "application/json"); r.raw != `{"dismissed":[],"host_order":[],"panels":null}` {
		t.Errorf("empty order: %s", r.raw)
	}
}

func TestOverviewHostOrderRefusesInvalidLists(t *testing.T) {
	_, mux := newHTTP(t)
	u := principaltest.User(2)
	tooMany := `["` + strings.Repeat(`h","`, HostOrderLimit) + `h"]`
	for _, body := range []string{
		`{"host_order":"web"}`, `{"host_order":{}}`, `{"host_order":[1]}`, `{"host_order":[null]}`,
		`{"host_order":["a","a"]}`, `{"host_order":[""]}`, `{"host_order":["` + strings.Repeat("x", hostOrderIDLimit+1) + `"]}`,
		`{"host_order":` + tooMany + `}`, `{"host_order":["a\u0000b"]}`,
		`{"panels":null,"host_order":5}`,
	} {
		r := call(t, mux, &u, "PUT", "/api/overview/preferences", body, "application/json")
		if r.status != 400 || r.body["code"] != "invalid_value" || r.body["error"] != msgInvalidHostOrder {
			t.Errorf("%.80s: %d %s", body, r.status, r.raw)
		}
	}
	if got := call(t, mux, &u, "PUT", "/api/overview/preferences", `{"dismissed":[]}`, "application/json"); strings.Contains(got.raw, "host_order") {
		t.Errorf("a refused list was stored: %s", got.raw)
	}
	// The longest allowed list and id are accepted.
	long := `["` + strings.Repeat("x", hostOrderIDLimit) + `"]`
	if r := call(t, mux, &u, "PUT", "/api/overview/preferences", `{"host_order":`+long+`}`, "application/json"); r.status != 200 {
		t.Errorf("longest id: %d %s", r.status, r.raw)
	}
}

func TestOverviewHostOrderOnThePage(t *testing.T) {
	s, _ := newService(t, Environment{})
	ring, err := keyring.Open([]byte("page-test-secret-0123456789abcdef"), make([]byte, keyring.MaterialSize))
	if err != nil {
		t.Fatal(err)
	}
	pp := PageProvider{Settings: s, Scope: ring}
	acct := Account{ID: 4, Username: "ada", HistoryGeneration: "2026-11-02T09:00:00"}
	if _, err := s.Update(t.Context(), 4, Changes{OverviewHostOrder: rawJSON(`["web","db"]`)}); err != nil {
		t.Fatal(err)
	}
	p, err := pp.Page(t.Context(), acct)
	if err != nil {
		t.Fatal(err)
	}
	if p.OverviewPreferencesJSON != `{"dismissed": [], "host_order": ["web", "db"], "panels": null}` {
		t.Errorf("page block %s", p.OverviewPreferencesJSON)
	}
}

func TestStoredHostOrderKeepsOnlyUsableEntries(t *testing.T) {
	// Written by a later release or by hand: entries that are not ids are
	// dropped on read instead of making the settings unreadable.
	u, ok := buildUser(map[string]jsontext.Value{keyOverviewHostOrder: rawJSON(`["a",5,"a","",null,"b"]`)})
	if !ok || !slices.Equal(u.OverviewHostOrder, []string{"a", "b"}) {
		t.Errorf("%v %v", ok, u.OverviewHostOrder)
	}
	if _, ok := buildUser(map[string]jsontext.Value{keyOverviewHostOrder: rawJSON(`"a"`)}); ok {
		t.Error("a stored order that is not a list loads")
	}
	if u, ok := buildUser(map[string]jsontext.Value{keyOverviewHostOrder: rawJSON(`null`)}); !ok || u.OverviewHostOrder != nil {
		t.Errorf("null: %v %v", ok, u.OverviewHostOrder)
	}
}
