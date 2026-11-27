package files

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
)

// Defaults of the directory snapshots (REMOTE_LISTING_*).
const (
	DefaultPageSize        = 500
	DefaultSnapshotTTL     = 60 * time.Second
	DefaultSnapshotsUser   = 4
	DefaultSnapshotsGlobal = 8
)

var (
	cursorPattern    = regexp.MustCompile(`^v1\.([A-Za-z0-9_-]{16,64})\.([1-9][0-9]{0,7})\.([0-9a-f]{32})$`)
	requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9:._-]{1,128}$`)

	errCursor   = fault.New(fault.InvalidRequest, "Invalid or expired directory cursor.")
	errListings = fault.New(fault.Busy, "Too many active directory listings. Try again in a moment.")
	errMembers  = fault.New(fault.LimitExceeded, "The directory exceeds the configured member limit.")
	errListGone = fault.New(fault.FileCancelled, "The directory listing was cancelled.")
)

// ValidRequestID reports whether id is a request id of the file pages.
func ValidRequestID(id string) bool { return requestIDPattern.MatchString(id) }

// owner binds a snapshot: user, browser session and realtime connection.
type owner struct {
	user    int64
	session string
	peer    uint64
}

type snapState int

const (
	snapOpening snapState = iota
	snapActive
	snapClosing
)

type snapshot struct {
	id        string
	owner     owner
	sourceID  string
	path      string
	requestID string

	// Guarded by listings.mu.
	state    snapState
	next     int
	lastUsed time.Time
	timer    *time.Timer
	cancel   context.CancelFunc

	read    sync.Mutex // one page read at a time
	listing Listing    // set once opened, guarded by read
	closed  chan struct{}
	once    sync.Once
}

// listings holds the open directory snapshots of the process. A cursor
// names a snapshot and its offset and carries a MAC under a per-process
// key over every binding, so it cannot be forged or moved to another
// connection, source or path.
type listings struct {
	pageSize, perUser, total, members int
	ttl                               time.Duration
	now                               func() time.Time
	key                               [32]byte

	mu    sync.Mutex
	snaps map[string]*snapshot
}

func newListings(o Options) *listings {
	l := &listings{
		pageSize: o.PageSize, perUser: o.SnapshotsPerUser, total: o.SnapshotsTotal,
		members: o.MaxMembers, ttl: o.SnapshotTTL, now: o.Now, snaps: map[string]*snapshot{},
	}
	_, _ = rand.Read(l.key[:]) // never fails (crypto/rand)
	return l
}

func (l *listings) mac(s *snapshot, offset int) string {
	m := hmac.New(sha256.New, l.key[:])
	for _, part := range []string{
		"files-cursor-v1", s.id, strconv.Itoa(offset), strconv.FormatInt(s.owner.user, 10),
		s.owner.session, strconv.FormatUint(s.owner.peer, 10), s.sourceID, s.path,
	} {
		m.Write([]byte(part))
		m.Write([]byte{0})
	}
	return hex.EncodeToString(m.Sum(nil))[:32]
}

func (l *listings) cursor(s *snapshot, offset int) string {
	return "v1." + s.id + "." + strconv.Itoa(offset) + "." + l.mac(s, offset)
}

// reserve registers an opening snapshot, evicting the owner's least
// recently used one when a limit is reached. Only the owner's own
// snapshots are evicted, so one user cannot push out another.
func (l *listings) reserve(o owner, sourceID, path, requestID string, cancel context.CancelFunc) (*snapshot, error) {
	var b [18]byte
	_, _ = rand.Read(b[:])
	s := &snapshot{
		id: base64.RawURLEncoding.EncodeToString(b[:]), owner: o, sourceID: sourceID, path: path,
		requestID: requestID, cancel: cancel, closed: make(chan struct{}), lastUsed: l.now(),
	}
	// The opener holds the read lock until the first page is in, so a
	// cancel waits for it and closes what it opened.
	s.read.Lock()
	for {
		l.mu.Lock()
		count := 0
		var oldest *snapshot
		for _, c := range l.snaps {
			if c.owner.user != o.user {
				continue
			}
			count++
			if c.state == snapActive && (oldest == nil || c.lastUsed.Before(oldest.lastUsed)) {
				oldest = c
			}
		}
		if count < l.perUser && len(l.snaps) < l.total {
			l.snaps[s.id] = s
			l.mu.Unlock()
			return s, nil
		}
		if oldest == nil {
			l.mu.Unlock()
			s.read.Unlock()
			return nil, errListings
		}
		oldest.state = snapClosing
		l.mu.Unlock()
		l.close(oldest)
	}
}

// opened publishes the listing of s after its first page; it reports
// false when s was cancelled meanwhile.
func (l *listings) opened(s *snapshot, offset int) (string, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.snaps[s.id] != s || s.state != snapOpening {
		return "", false
	}
	s.state, s.next, s.cancel = snapActive, offset, nil
	l.armLocked(s)
	return l.cursor(s, offset), true
}

func (l *listings) armLocked(s *snapshot) {
	s.lastUsed = l.now()
	if s.timer != nil {
		s.timer.Stop()
	}
	s.timer = time.AfterFunc(l.ttl, func() { l.expire(s) })
}

func (l *listings) expire(s *snapshot) {
	l.mu.Lock()
	idle := l.snaps[s.id] == s && s.state == snapActive && l.now().Sub(s.lastUsed) >= l.ttl
	if idle {
		s.state = snapClosing
	}
	l.mu.Unlock()
	if idle {
		l.close(s)
	}
}

// find returns the active snapshot a continuation cursor names, after
// checking its MAC and that o, sourceID and path match exactly.
func (l *listings) find(cursor string, o owner, sourceID, path string) (*snapshot, int, error) {
	m := cursorPattern.FindStringSubmatch(cursor)
	if m == nil {
		return nil, 0, errCursor
	}
	offset, _ := strconv.Atoi(m[2])
	l.mu.Lock()
	defer l.mu.Unlock()
	s, ok := l.snaps[m[1]]
	if !ok || s.state != snapActive || !hmac.Equal([]byte(m[3]), []byte(l.mac(s, offset))) ||
		s.owner != o || s.sourceID != sourceID || (path != "" && s.path != path) {
		return nil, 0, errCursor
	}
	return s, offset, nil
}

// at reports whether s is active at offset.
func (l *listings) at(s *snapshot, offset int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.snaps[s.id] == s && s.state == snapActive && s.next == offset
}

// advance records a continuation page; false means s ended meanwhile.
func (l *listings) advance(s *snapshot, offset, n int) (string, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.snaps[s.id] != s || s.state != snapActive || s.next != offset {
		return "", false
	}
	s.next = offset + n
	l.armLocked(s)
	return l.cursor(s, s.next), true
}

// retire ends s and waits until its listing is closed.
func (l *listings) retire(s *snapshot) {
	l.mu.Lock()
	s.state = snapClosing
	l.mu.Unlock()
	l.close(s)
}

// close ends s once: it stops a running open, waits for the page read in
// progress, closes the listing and removes s.
func (l *listings) close(s *snapshot) {
	l.mu.Lock()
	cancel := s.cancel
	if s.timer != nil {
		s.timer.Stop()
	}
	l.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	s.once.Do(func() {
		s.read.Lock()
		if s.listing != nil {
			_ = s.listing.Close()
			s.listing = nil
		}
		s.read.Unlock()
		l.mu.Lock()
		if l.snaps[s.id] == s {
			delete(l.snaps, s.id)
		}
		l.mu.Unlock()
		close(s.closed)
	})
	<-s.closed
}

// cancelCursor closes the snapshot of an owned cursor. The answer never
// says whether it existed.
func (l *listings) cancelCursor(cursor string, o owner, sourceID string) {
	if s, _, err := l.find(cursor, o, sourceID, ""); err == nil {
		l.retire(s)
	}
}

// cancelRequest stops the first page of an owned request, also while it
// is still opening, and waits until its listing is closed.
func (l *listings) cancelRequest(requestID string, o owner, sourceID string) {
	if !ValidRequestID(requestID) {
		return
	}
	l.discard(func(s *snapshot) bool { return s.requestID == requestID && s.owner == o && s.sourceID == sourceID })
}

// discard ends every matching snapshot.
func (l *listings) discard(match func(*snapshot) bool) {
	var hit []*snapshot
	l.mu.Lock()
	for _, s := range l.snaps {
		if match(s) {
			s.state = snapClosing
			hit = append(hit, s)
		}
	}
	l.mu.Unlock()
	for _, s := range hit {
		l.close(s)
	}
}
