package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
)

// Bounds of the flight store: a browser keeps at most
// MaxFlightsPerBinding redirects in progress (oidc_service.py
// _MAX_STATES_PER_BINDING), the process at most maxFlights; the oldest
// give way.
const (
	MaxFlightsPerBinding = 8
	maxFlights           = 4096
)

// Flights holds the redirect flights of the external providers in
// memory, keyed by a digest of the state and bound to the browser
// binding. A flight is taken exactly once. The store needs no table: a
// flight lives five minutes and holds a nonce and a PKCE verifier that
// should not outlive the process; a restart only makes running redirects
// start again.
type Flights struct {
	Now func() time.Time

	mu  sync.Mutex
	m   map[[32]byte]storedFlight
	seq uint64 // insertion order, for eviction
}

type storedFlight struct {
	binding [32]byte
	flight  Flight
	expires time.Time
	seq     uint64
}

func (s *Flights) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func digest(v string) [32]byte { return sha256.Sum256([]byte(v)) }

var errFlight = fault.New(fault.AuthFailed, "")

// Put stores f for the browser binding until f.IssuedAt plus FlightTTL.
// A browser without binding cannot start a redirect.
func (s *Flights) Put(binding string, f Flight) error {
	if binding == "" || f.State == "" || len(f.State) > maxCallbackField {
		return fault.New(fault.InvalidRequest, "")
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[[32]byte]storedFlight{}
	}
	b := digest(binding)
	var mine [][32]byte
	for k, v := range s.m {
		switch {
		case !now.Before(v.expires):
			delete(s.m, k)
		case v.binding == b:
			mine = append(mine, k)
		}
	}
	for len(mine) >= MaxFlightsPerBinding {
		s.dropOldest(mine)
		mine = s.keysOf(b)
	}
	if len(s.m) >= maxFlights {
		s.dropOldest(nil)
	}
	s.seq++
	s.m[digest(f.State)] = storedFlight{binding: b, flight: f, expires: f.IssuedAt.Add(FlightTTL), seq: s.seq}
	return nil
}

func (s *Flights) keysOf(b [32]byte) [][32]byte {
	var out [][32]byte
	for k, v := range s.m {
		if v.binding == b {
			out = append(out, k)
		}
	}
	return out
}

// dropOldest removes the oldest flight among keys (all flights for nil).
func (s *Flights) dropOldest(keys [][32]byte) {
	var oldest [32]byte
	found := false
	var seq uint64
	consider := func(k [32]byte, v storedFlight) {
		if !found || v.seq < seq {
			oldest, seq, found = k, v.seq, true
		}
	}
	if keys == nil {
		for k, v := range s.m {
			consider(k, v)
		}
	} else {
		for _, k := range keys {
			consider(k, s.m[k])
		}
	}
	if found {
		delete(s.m, oldest)
	}
}

// Take returns and removes the flight of state for the browser binding.
// A flight of another browser is neither returned nor removed; an expired
// one is removed and refused. Every refusal is fault.AuthFailed.
func (s *Flights) Take(binding, state string) (Flight, error) {
	if binding == "" || state == "" || len(state) > maxCallbackField {
		return Flight{}, errFlight
	}
	key, b := digest(state), digest(binding)
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[key]
	if !ok || subtle.ConstantTimeCompare(v.binding[:], b[:]) != 1 {
		return Flight{}, errFlight
	}
	delete(s.m, key)
	if !s.now().Before(v.expires) {
		return Flight{}, errFlight
	}
	return v.flight, nil
}

// Drop removes the flight of state for the binding, for a redirect that
// could not be started.
func (s *Flights) Drop(binding, state string) {
	key, b := digest(state), digest(binding)
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.m[key]; ok && v.binding == b {
		delete(s.m, key)
	}
}
