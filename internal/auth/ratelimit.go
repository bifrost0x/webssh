package auth

import (
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Rule is a parsed rate limit: Limit events per Window.
type Rule struct {
	Limit  int
	Window time.Duration
}

// ParseRule reads the Flask-Limiter notation the configuration uses
// ("5 per minute", "200 per hours"), as parse_rate_limit does: the first
// word is the count, the last word the unit (second, minute or hour, with
// an optional plural s). Anything else gives def.
func ParseRule(s string, def Rule) Rule {
	parts := strings.Fields(strings.ToLower(s))
	if len(parts) == 0 {
		return def
	}
	n, err := strconv.Atoi(parts[0])
	if err != nil {
		return def
	}
	var window time.Duration
	switch strings.TrimRight(parts[len(parts)-1], "s") {
	case "second":
		window = time.Second
	case "minute":
		window = time.Minute
	case "hour":
		window = time.Hour
	default:
		return def
	}
	return Rule{Limit: n, Window: window}
}

// Default rules of parse_rate_limit.
var (
	DefaultRule         = Rule{Limit: 5, Window: time.Minute}
	DefaultUsernameRule = Rule{Limit: 10, Window: time.Minute}
	DefaultGlobalRule   = Rule{Limit: 100, Window: time.Minute}
)

// Limiter is the in-process sliding-window limiter (decision D-16: no
// Redis; counters live in the one process). Only allowed events are
// recorded, so refused requests cannot grow a bucket. It is safe for
// concurrent use; every call does constant work apart from the events of
// its own bucket.
//
// Buckets live in two pools of maxBuckets each. Source buckets (Reserve,
// Allow: keys that contain a client address) are cheap to create with
// fresh addresses; at capacity the least recently used one is dropped,
// because refusing new sources would let a flood lock every user out.
// Account buckets (ReserveAccount, AllowAccount: the ceilings per name,
// account and known device) never compete with source buckets, so a
// flood of fresh sources cannot reset them. At capacity an account
// bucket that has reached its limit is kept; a new key is refused when
// no other bucket near the eviction end can make room.
type Limiter struct {
	mu       sync.Mutex
	sources  pool
	accounts pool
	seq      uint64
	// Now replaces the clock in tests.
	Now func() time.Time
	// Realtime maps realtime RateKeys to their rule; unknown keys use
	// RealtimeDefault.
	Realtime        map[string]Rule
	RealtimeDefault Rule
}

// NewLimiter returns an empty limiter.
func NewLimiter() *Limiter {
	return &Limiter{
		sources:  pool{buckets: map[string]*bucket{}},
		accounts: pool{buckets: map[string]*bucket{}, keepFull: true},
		Now:      time.Now, RealtimeDefault: Rule{Limit: 200, Window: time.Hour},
	}
}

// Reservation identifies one recorded event, for Release.
type Reservation struct {
	key     string
	id      uint64
	account bool
}

// Reserve records one event under the source key key if fewer than
// r.Limit events are in the window. It returns the reservation, or ok
// false and how long to wait.
func (l *Limiter) Reserve(key string, r Rule) (res Reservation, ok bool, retryAfter time.Duration) {
	return l.reserve(&l.sources, key, r)
}

// ReserveAccount is Reserve for a ceiling per name, account or device.
func (l *Limiter) ReserveAccount(key string, r Rule) (res Reservation, ok bool, retryAfter time.Duration) {
	res, ok, retryAfter = l.reserve(&l.accounts, key, r)
	res.account = true
	return res, ok, retryAfter
}

func (l *Limiter) reserve(p *pool, key string, r Rule) (Reservation, bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if p.buckets == nil {
		p.buckets = map[string]*bucket{}
	}
	now := l.Now()
	p.expireTail(now)
	b := p.buckets[key]
	if b != nil {
		b.trim(now, r.Window)
	}
	if r.Limit <= 0 {
		return Reservation{}, false, r.Window
	}
	if b != nil && len(b.events) >= r.Limit {
		b.limit = r.Limit
		p.touch(b)
		return Reservation{}, false, max(time.Second, b.events[0].at.Add(r.Window).Sub(now))
	}
	if b == nil {
		if len(p.buckets) >= maxBuckets && !p.makeRoom(now) {
			return Reservation{}, false, time.Second
		}
		b = &bucket{key: key}
		p.buckets[key] = b
	}
	b.window = max(b.window, r.Window)
	b.limit = r.Limit
	l.seq++
	b.events = append(b.events, event{at: now, id: l.seq})
	p.touch(b)
	return Reservation{key: key, id: l.seq}, true, 0
}

// Allow is Reserve without keeping the reservation.
func (l *Limiter) Allow(key string, r Rule) (bool, time.Duration) {
	_, ok, after := l.Reserve(key, r)
	return ok, after
}

// AllowAccount is ReserveAccount without keeping the reservation.
func (l *Limiter) AllowAccount(key string, r Rule) (bool, time.Duration) {
	_, ok, after := l.ReserveAccount(key, r)
	return ok, after
}

// Release returns reserved events, for limits that count only failures:
// the caller reserves before the check and releases after a success.
func (l *Limiter) Release(res ...Reservation) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, r := range res {
		p := &l.sources
		if r.account {
			p = &l.accounts
		}
		b := p.buckets[r.key]
		if b == nil {
			continue
		}
		for i, e := range b.events {
			if e.id == r.id {
				b.events = append(b.events[:i], b.events[i+1:]...)
				break
			}
		}
		if len(b.events) == 0 {
			p.remove(b)
		}
	}
}

// AllowUser is the per-account limit of realtime messages
// (realtime.Limiter): key is the route's RateKey.
func (l *Limiter) AllowUser(userID int64, key string) (bool, time.Duration) {
	rule, ok := l.Realtime[key]
	if !ok {
		rule = l.RealtimeDefault
	}
	return l.AllowAccount(key+":user:"+strconv.FormatInt(userID, 10), rule)
}

// Realtime adapts the limiter to realtime.Limiter.
type Realtime struct{ L *Limiter }

// Allow implements realtime.Limiter.
func (r Realtime) Allow(userID int64, key string) (bool, time.Duration) {
	return r.L.AllowUser(userID, key)
}

// SourceBucket is rate_limit_address: IPv4 and IPv4-mapped addresses keep
// one bucket per address, IPv6 addresses share one bucket per network of
// prefix bits (48–128, the sign-in protection setting), and values that
// are not addresses stay as they are.
func SourceBucket(address string, prefix int) string {
	a, err := netip.ParseAddr(strings.TrimSpace(address))
	if err != nil {
		if address == "" {
			return "unknown"
		}
		return address
	}
	a = a.Unmap().WithZone("")
	if a.Is4() {
		return a.String()
	}
	if prefix < 48 || prefix > 128 {
		prefix = 128
	}
	if prefix == 128 {
		return a.String()
	}
	p, err := a.Prefix(prefix)
	if err != nil {
		return a.String()
	}
	return p.String()
}
