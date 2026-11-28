package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"strconv"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
)

// Bounds of the flight store. A browser keeps at most
// MaxFlightsPerBinding redirects in progress (oidc_service.py
// _MAX_STATES_PER_BINDING) and a source at most maxFlightsPerSource; the
// oldest gives way. Sign-in starts and the link and step-up flights of
// signed-in accounts have separate pools of maxFlights and
// maxAccountFlights, so unauthenticated starts never block an account.
// A full pool gives way at the source holding the most flights in it:
// a flood from many addresses pushes out its own flights first, and
// other browsers keep theirs and can still start.
const (
	MaxFlightsPerBinding = 8
	maxFlightsPerSource  = 16
	maxFlights           = 4096
	maxAccountFlights    = 4096
	// flightSourcePrefix groups IPv6 sources by /64, the usual
	// allocation of one subscriber, whatever RATELIMIT_IPV6_PREFIX says.
	flightSourcePrefix = 64
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
	// source is the client source of a sign-in start, or the account of
	// a link or step-up flight (account set).
	source  string
	account bool
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

var (
	errFlight = fault.New(fault.AuthFailed, "")
)

// Put stores f for the browser binding until f.IssuedAt plus FlightTTL.
// address is the client address of the start; flights with a UserID count
// against the account instead. A browser without binding cannot start a
// redirect.
func (s *Flights) Put(binding, address string, f Flight) error {
	if binding == "" || f.State == "" || len(f.State) > maxCallbackField {
		return fault.New(fault.InvalidRequest, "")
	}
	account := f.UserID != 0
	source := "addr:" + SourceBucket(address, flightSourcePrefix)
	limit := maxFlights
	if account {
		source, limit = "user:"+strconv.FormatInt(f.UserID, 10), maxAccountFlights
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[[32]byte]storedFlight{}
	}
	b := digest(binding)
	for k, v := range s.m {
		if !now.Before(v.expires) {
			delete(s.m, k)
		}
	}
	for {
		mine := s.keys(func(v storedFlight) bool { return v.binding == b })
		if len(mine) < MaxFlightsPerBinding {
			break
		}
		s.dropOldest(mine)
	}
	for {
		same := s.keys(func(v storedFlight) bool { return v.account == account && v.source == source })
		if len(same) < maxFlightsPerSource {
			break
		}
		s.dropOldest(same)
	}
	if pool := s.keys(func(v storedFlight) bool { return v.account == account }); len(pool) >= limit {
		s.dropOldest(s.largestSource(pool))
	}
	s.seq++
	s.m[digest(f.State)] = storedFlight{binding: b, source: source, account: account, flight: f,
		expires: f.IssuedAt.Add(FlightTTL), seq: s.seq}
	return nil
}

func (s *Flights) keys(match func(storedFlight) bool) [][32]byte {
	var out [][32]byte
	for k, v := range s.m {
		if match(v) {
			out = append(out, k)
		}
	}
	return out
}

// largestSource returns the flights of pool that belong to the source
// holding the most of them.
func (s *Flights) largestSource(pool [][32]byte) [][32]byte {
	by := map[string][][32]byte{}
	var top string
	for _, k := range pool {
		src := s.m[k].source
		by[src] = append(by[src], k)
		if len(by[src]) > len(by[top]) {
			top = src
		}
	}
	return by[top]
}

// dropOldest removes the oldest flight among keys.
func (s *Flights) dropOldest(keys [][32]byte) {
	var oldest [32]byte
	found := false
	var seq uint64
	for _, k := range keys {
		if v := s.m[k]; !found || v.seq < seq {
			oldest, seq, found = k, v.seq, true
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
