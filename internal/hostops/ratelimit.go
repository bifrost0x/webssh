package hostops

import (
	"sync"
	"time"
)

// maxRateKeys bounds the tracked keys of one window; the oldest key is
// dropped first, so memory stays bounded whatever the number of users.
const maxRateKeys = 4096

// rateWindow allows limit events per key within each window
// (check_socket_rate_limit of the Python release). Every call counts.
type rateWindow struct {
	limit  int
	window time.Duration

	mu   sync.Mutex
	hits map[int64][]time.Time
}

func (w *rateWindow) allow(user int64, now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.hits == nil {
		w.hits = map[int64][]time.Time{}
	}
	cut := now.Add(-w.window)
	recent := w.hits[user][:0]
	for _, at := range w.hits[user] {
		if at.After(cut) {
			recent = append(recent, at)
		}
	}
	if _, known := w.hits[user]; !known && len(w.hits) >= maxRateKeys {
		w.evict(cut)
	}
	if len(recent) >= w.limit {
		w.hits[user] = recent
		return false
	}
	w.hits[user] = append(recent, now)
	return true
}

// evict removes users without recent events, or else the one whose last
// event is oldest.
func (w *rateWindow) evict(cut time.Time) {
	var oldest int64
	var at time.Time
	first := true
	for u, hits := range w.hits {
		if len(hits) == 0 || !hits[len(hits)-1].After(cut) {
			delete(w.hits, u)
			continue
		}
		if last := hits[len(hits)-1]; first || last.Before(at) {
			oldest, at, first = u, hits[len(hits)-1], false
		}
	}
	if len(w.hits) >= maxRateKeys && !first {
		delete(w.hits, oldest)
	}
}
