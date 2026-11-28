package auth

import (
	"fmt"
	"strconv"
	"testing"
	"time"
)

// A flood of unauthenticated starts from many addresses (each start with a
// fresh binding) must neither refuse nor push out the sign-in start of a
// browser elsewhere, nor block link and step-up flights of signed-in
// accounts.
func TestFlightsFloodKeepsOtherSourcesAndAccounts(t *testing.T) {
	now := time.Now().UTC()
	s := &Flights{Now: func() time.Time { return now }}
	put := func(binding, source string, f Flight) error { return s.Put(binding, source, f) }
	for i := range 2 * maxFlights {
		// 512 addresses of one IPv6 /56, many starts each.
		src := fmt.Sprintf("2001:db8:0:%x::%x", i%256, i)
		if err := put("attacker-"+strconv.Itoa(i), src, NewFlight(ProviderOIDC, PurposeSignIn, now)); err != nil {
			t.Fatalf("start %d refused: %v", i, err)
		}
	}
	victim := NewFlight(ProviderOIDC, PurposeSignIn, now)
	if err := put("victim", "192.0.2.10", victim); err != nil {
		t.Fatalf("victim start refused: %v", err)
	}
	stepUp := NewFlight(ProviderOIDC, PurposeStepUp, now)
	stepUp.UserID, stepUp.SessionID = 1, "s1"
	if err := put("admin", "192.0.2.11", stepUp); err != nil {
		t.Fatalf("step-up start refused: %v", err)
	}
	for i := range maxFlights {
		src := fmt.Sprintf("2001:db8:0:%x::%x", i%256, i+7)
		_ = put("attacker2-"+strconv.Itoa(i), src, NewFlight(ProviderOIDC, PurposeSignIn, now))
	}
	if _, err := s.Take("victim", victim.State); err != nil {
		t.Fatalf("victim flight pushed out: %v", err)
	}
	if _, err := s.Take("admin", stepUp.State); err != nil {
		t.Fatalf("step-up flight pushed out: %v", err)
	}
	if len(s.m) > maxFlights+maxAccountFlights {
		t.Fatalf("%d flights stored", len(s.m))
	}
}

// One source keeps at most maxFlightsPerSource flights; its oldest gives
// way, flights of other sources stay.
func TestFlightsPerSourceQuota(t *testing.T) {
	now := time.Now().UTC()
	s := &Flights{Now: func() time.Time { return now }}
	other := NewFlight(ProviderOIDC, PurposeSignIn, now)
	if err := s.Put("other", "198.51.100.1", other); err != nil {
		t.Fatal(err)
	}
	var first Flight
	for i := range maxFlightsPerSource + 5 {
		f := NewFlight(ProviderOIDC, PurposeSignIn, now)
		if i == 0 {
			first = f
		}
		// Addresses of one /64 are one source.
		if err := s.Put("b"+strconv.Itoa(i), fmt.Sprintf("2001:db8:1:2::%x", i+1), f); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(s.m); n != maxFlightsPerSource+1 {
		t.Fatalf("%d flights stored", n)
	}
	if _, err := s.Take("b0", first.State); err == nil {
		t.Fatal("oldest flight of the full source kept")
	}
	if _, err := s.Take("other", other.State); err != nil {
		t.Fatal(err)
	}
}
