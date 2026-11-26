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

// maxBuckets bounds the limiter's memory. When it is reached and expired
// buckets cannot make room, the bucket that was used least recently is
// dropped. Refusing new keys instead would let a flood of fresh sources
// lock every user out; dropping old buckets only forgets attempts that
// lie furthest back.
const maxBuckets = 1 << 16

type event struct {
	at time.Time
	id uint64
}

type bucket struct {
	events []event
	window time.Duration
}

// Limiter is the in-process sliding-window limiter (decision D-16: no
// Redis; counters live in the one process). Only allowed events are
// recorded, so refused requests cannot grow a bucket. It is safe for
// concurrent use.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	seq     uint64
	lastGC  time.Time
	// Now replaces the clock in tests.
	Now func() time.Time
	// Realtime maps realtime RateKeys to their rule; unknown keys use
	// RealtimeDefault.
	Realtime        map[string]Rule
	RealtimeDefault Rule
}

// NewLimiter returns an empty limiter.
func NewLimiter() *Limiter {
	return &Limiter{buckets: map[string]*bucket{}, Now: time.Now, RealtimeDefault: Rule{Limit: 200, Window: time.Hour}}
}

// Reservation identifies one recorded event, for Release.
type Reservation struct {
	key string
	id  uint64
}

func (l *Limiter) gc(now time.Time, force bool) {
	if !force && now.Sub(l.lastGC) < time.Minute {
		return
	}
	l.lastGC = now
	for k, b := range l.buckets {
		if len(b.events) == 0 || !b.events[len(b.events)-1].at.Add(b.window).After(now) {
			delete(l.buckets, k)
		}
	}
}

// Reserve records one event under key if fewer than r.Limit events are
// in the window. It returns the reservation, or ok false and how long to
// wait.
func (l *Limiter) Reserve(key string, r Rule) (res Reservation, ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.Now()
	l.gc(now, false)
	b := l.buckets[key]
	if b != nil {
		keep := b.events[:0]
		for _, e := range b.events {
			if e.at.Add(r.Window).After(now) {
				keep = append(keep, e)
			}
		}
		b.events = keep
	}
	if r.Limit <= 0 {
		return Reservation{}, false, r.Window
	}
	if b != nil && len(b.events) >= r.Limit {
		return Reservation{}, false, max(time.Second, b.events[0].at.Add(r.Window).Sub(now))
	}
	if b == nil {
		if len(l.buckets) >= maxBuckets {
			l.gc(now, true)
			if len(l.buckets) >= maxBuckets {
				l.evictOldest()
			}
		}
		b = &bucket{}
		l.buckets[key] = b
	}
	b.window = max(b.window, r.Window)
	l.seq++
	b.events = append(b.events, event{at: now, id: l.seq})
	return Reservation{key: key, id: l.seq}, true, 0
}

func (l *Limiter) evictOldest() {
	var oldest string
	var at time.Time
	for k, b := range l.buckets {
		if len(b.events) == 0 {
			delete(l.buckets, k)
			return
		}
		last := b.events[len(b.events)-1].at
		if oldest == "" || last.Before(at) {
			oldest, at = k, last
		}
	}
	delete(l.buckets, oldest)
}

// Allow is Reserve without keeping the reservation.
func (l *Limiter) Allow(key string, r Rule) (bool, time.Duration) {
	_, ok, after := l.Reserve(key, r)
	return ok, after
}

// Release returns reserved events, for limits that count only failures:
// the caller reserves before the check and releases after a success.
func (l *Limiter) Release(res ...Reservation) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, r := range res {
		b := l.buckets[r.key]
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
			delete(l.buckets, r.key)
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
	return l.Allow(key+":user:"+strconv.FormatInt(userID, 10), rule)
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
