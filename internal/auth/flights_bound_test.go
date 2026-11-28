package auth

import (
	"strconv"
	"testing"
	"time"
)

// Unauthenticated starts from many browser bindings (a binding is any
// valid cookie value the client chooses) must not push a victim's
// flight out of the process-wide store before its callback arrives
// (RS2-06), and must not refuse a start of another source either.
func TestFlightsFullStoreKeepsOtherBrowsers(t *testing.T) {
	now := time.Now().UTC()
	s := &Flights{Now: func() time.Time { return now }}
	victim := NewFlight(ProviderOIDC, PurposeSignIn, now)
	if err := s.Put("victim", "192.0.2.1", victim); err != nil {
		t.Fatal(err)
	}
	attacker := func(i int) string { return "10.0." + strconv.Itoa(i/256) + "." + strconv.Itoa(i%256) }
	for i := range maxFlights {
		if err := s.Put("attacker-"+strconv.Itoa(i), attacker(i%300), NewFlight(ProviderOIDC, PurposeSignIn, now)); err != nil {
			t.Fatalf("start %d refused: %v", i, err)
		}
	}
	if _, err := s.Take("victim", victim.State); err != nil {
		t.Fatalf("victim flight evicted by %d foreign starts: %v", maxFlights, err)
	}
	if len(s.m) > maxFlights {
		t.Fatalf("%d flights stored", len(s.m))
	}
	now = now.Add(FlightTTL)
	if err := s.Put("late", "192.0.2.2", NewFlight(ProviderOIDC, PurposeSignIn, now)); err != nil {
		t.Fatalf("expired flights did not make room: %v", err)
	}
	if len(s.m) != 1 {
		t.Fatalf("%d flights after expiry", len(s.m))
	}
}
