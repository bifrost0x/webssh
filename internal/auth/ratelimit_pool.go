package auth

import "time"

// maxBuckets bounds the memory of each pool of the limiter.
const maxBuckets = 1 << 16

// expirePerCall bounds how many expired buckets one call removes from
// the eviction end, and evictScan how many buckets at capacity are looked
// at for room; both keep every call constant work.
const (
	expirePerCall = 4
	evictScan     = 8
)

type event struct {
	at time.Time
	id uint64
}

// bucket holds the recorded events of one key. prev and next link the
// pool's recency list: head is the bucket used last, tail the one used
// longest ago.
type bucket struct {
	key        string
	events     []event
	window     time.Duration
	limit      int
	prev, next *bucket
}

// trim drops the events that left window.
func (b *bucket) trim(now time.Time, window time.Duration) {
	keep := b.events[:0]
	for _, e := range b.events {
		if e.at.Add(window).After(now) {
			keep = append(keep, e)
		}
	}
	clear(b.events[len(keep):])
	b.events = keep
}

// expired reports whether no event of b is inside its window any more.
func (b *bucket) expired(now time.Time) bool {
	return len(b.events) == 0 || !b.events[len(b.events)-1].at.Add(b.window).After(now)
}

// full reports whether b still holds as many live events as its limit.
func (b *bucket) full(now time.Time) bool {
	if b.limit <= 0 || len(b.events) < b.limit {
		return false
	}
	return b.events[len(b.events)-b.limit].at.Add(b.window).After(now)
}

// pool is one set of buckets with its recency list. keepFull keeps
// buckets at their limit when room is needed.
type pool struct {
	buckets    map[string]*bucket
	head, tail *bucket
	keepFull   bool
}

func (p *pool) unlink(b *bucket) {
	if b.prev != nil {
		b.prev.next = b.next
	} else if p.head == b {
		p.head = b.next
	}
	if b.next != nil {
		b.next.prev = b.prev
	} else if p.tail == b {
		p.tail = b.prev
	}
	b.prev, b.next = nil, nil
}

// touch moves b to the head of the recency list.
func (p *pool) touch(b *bucket) {
	if p.head == b {
		return
	}
	p.unlink(b)
	b.next = p.head
	if p.head != nil {
		p.head.prev = b
	}
	p.head = b
	if p.tail == nil {
		p.tail = b
	}
}

func (p *pool) remove(b *bucket) {
	p.unlink(b)
	delete(p.buckets, b.key)
}

// expireTail removes expired buckets from the eviction end. Buckets used
// longest ago expire first, so this keeps the pool small without a scan.
func (p *pool) expireTail(now time.Time) {
	for range expirePerCall {
		if p.tail == nil || !p.tail.expired(now) {
			return
		}
		p.remove(p.tail)
	}
}

// makeRoom frees one place at capacity: the first expired bucket from
// the eviction end, else the bucket used longest ago, skipping buckets at
// their limit when keepFull is set. Skipped buckets move to the head, so
// the next call looks at others. It reports false when no place was
// freed.
func (p *pool) makeRoom(now time.Time) bool {
	for range evictScan {
		b := p.tail
		if b == nil {
			return true
		}
		if b.expired(now) || !p.keepFull || !b.full(now) {
			p.remove(b)
			return true
		}
		p.touch(b)
	}
	return false
}
