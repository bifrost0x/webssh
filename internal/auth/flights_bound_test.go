package auth

import (
	"strconv"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
)

// Unauthenticated starts from many browser bindings (a binding is any
// valid cookie value the client chooses) must not push a victim's
// flight out of the process-wide store before its callback arrives
// (RS2-06). A full store refuses the new start instead.
func TestFlightsFullStoreKeepsOtherBrowsers(t *testing.T) {
	now := time.Now().UTC()
	s := &Flights{Now: func() time.Time { return now }}
	victim := NewFlight(ProviderOIDC, PurposeSignIn, now)
	if err := s.Put("victim", victim); err != nil {
		t.Fatal(err)
	}
	refused := 0
	for i := range maxFlights {
		if err := s.Put("attacker-"+strconv.Itoa(i), NewFlight(ProviderOIDC, PurposeSignIn, now)); err != nil {
			if !fault.Is(err, fault.Unavailable) {
				t.Fatalf("full store: %v", err)
			}
			refused++
		}
	}
	if refused != 1 {
		t.Fatalf("%d starts refused, want 1", refused)
	}
	if _, err := s.Take("victim", victim.State); err != nil {
		t.Fatalf("victim flight evicted by %d foreign starts: %v", maxFlights, err)
	}
	// A browser with a flight in a full store replaces its own oldest.
	if err := s.Put("filler", NewFlight(ProviderOIDC, PurposeSignIn, now)); err != nil {
		t.Fatal(err)
	}
	if err := s.Put("attacker-0", NewFlight(ProviderOIDC, PurposeSignIn, now)); err != nil {
		t.Fatalf("own browser refused in a full store: %v", err)
	}
	if len(s.m) > maxFlights {
		t.Fatalf("%d flights stored", len(s.m))
	}
	now = now.Add(FlightTTL)
	if err := s.Put("late", NewFlight(ProviderOIDC, PurposeSignIn, now)); err != nil {
		t.Fatalf("expired flights did not make room: %v", err)
	}
}
