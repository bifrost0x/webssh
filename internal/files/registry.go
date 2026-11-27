package files

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

// Opener opens a source of a registered kind on first use; handle is the
// handle part of the source id. It runs without registry locks and must
// honour ctx. The registry closes the backend when the source ends.
type Opener func(ctx context.Context, p principal.Principal, handle string) (Descriptor, Backend, error)

// Quotas reserves runtime quota (provided by internal/quota).
type Quotas interface {
	Reserve(ctx context.Context, kind string, userID int64, amount int64) (release func(), err error)
}

// quickConnection is the quota kind of Quick SFTP and SMB sources.
const quickConnection = "quick_connection"

// DefaultSMBIdle is how long an SMB source stays open without use (the
// idle limit of the Python SMB pool).
const DefaultSMBIdle = 300 * time.Second

// RegistryOptions configure a Registry; zero values take the defaults.
type RegistryOptions struct {
	// Quotas, when set, bounds Quick SFTP and SMB sources per user and in
	// total (quota "quick_connection").
	Quotas Quotas
	// SMBIdle closes SMB sources unused for this long (Sweep).
	SMBIdle time.Duration
	// Now is the clock (tests).
	Now func() time.Time
}

var errUnavailable = fault.New(fault.SourceUnavailable, "")

type sourceKey struct {
	session string
	id      string
}

type source struct {
	key     sourceKey
	kind    SourceKind
	userID  int64
	desc    Descriptor
	backend Backend
	quota   func()

	holds    int
	closing  bool // no new holds; closed when the last hold ends
	closed   bool
	lastUsed time.Time
}

// opening is a first-use open in progress; waiters share its result.
type opening struct {
	done chan struct{}
	err  error
}

// Registry holds the open file sources of every browser session. A source
// belongs to the user and the browser session that opened it; every other
// caller gets fault.SourceUnavailable, as in the Python release.
type Registry struct {
	opts RegistryOptions

	mu      sync.Mutex
	kinds   map[SourceKind]Opener
	sources map[sourceKey]*source
	opening map[sourceKey]*opening
	peers   map[int64]map[uint64]bool
	onClose []func(session, sourceID string)
}

// NewRegistry returns an empty registry.
func NewRegistry(o RegistryOptions) *Registry {
	if o.SMBIdle <= 0 {
		o.SMBIdle = DefaultSMBIdle
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Registry{
		opts: o, kinds: map[SourceKind]Opener{}, sources: map[sourceKey]*source{},
		opening: map[sourceKey]*opening{}, peers: map[int64]map[uint64]bool{},
	}
}

// RegisterKind makes sources of kind open on first use (sftp-session: the
// SFTP subsystem of a terminal session). It is called while wiring.
func (r *Registry) RegisterKind(kind SourceKind, open Opener) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.kinds[kind] = open
}

// OnClose registers f, called after a source ended (snapshots of its
// listings are dropped there).
func (r *Registry) OnClose(f func(session, sourceID string)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onClose = append(r.onClose, f)
}

// Add registers an open backend for the principal and returns its new
// source id. Add takes ownership of b: on failure b is closed. Quick SFTP
// and SMB sources reserve quota "quick_connection" first; Reserve does
// that before the connection is made.
func (r *Registry) Add(p principal.Principal, kind SourceKind, d Descriptor, b Backend) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	slot, err := r.Reserve(ctx, p, kind)
	if err != nil {
		_ = b.Close()
		return "", err
	}
	return slot.Add(d, b)
}

func (r *Registry) insert(p principal.Principal, kind SourceKind, d Descriptor, b Backend, release func()) error {
	if p.UserID == 0 || p.SessionID == "" {
		return errUnavailable
	}
	key := sourceKey{p.SessionID, d.SourceID}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.sources[key]; dup {
		return errUnavailable
	}
	r.sources[key] = &source{key: key, kind: kind, userID: p.UserID, desc: d, backend: b, quota: release, lastUsed: r.opts.Now()}
	return nil
}

func newHandle() string {
	var b [18]byte
	_, _ = rand.Read(b[:]) // never fails (crypto/rand)
	// A handle starts with a letter or digit (validHandle).
	return "h" + base64.RawURLEncoding.EncodeToString(b[:])
}

// Resolve returns the backend of sourceID for p if the source belongs to
// p's user and browser session and offers need. The release function ends
// the hold; until then the source stays open (a Close is deferred), unless
// a revocation closes it. A registered kind opens on first use.
func (r *Registry) Resolve(ctx context.Context, p principal.Principal, sourceID string, need Capability) (Backend, func(), error) {
	kind, handle, err := ParseSourceID(sourceID)
	if err != nil || p.UserID == 0 || p.SessionID == "" {
		return nil, nil, errUnavailable
	}
	key := sourceKey{p.SessionID, sourceID}
	for {
		r.mu.Lock()
		if s, ok := r.sources[key]; ok {
			defer r.mu.Unlock()
			return r.hold(s, p, need)
		}
		open, registered := r.kinds[kind]
		if !registered {
			r.mu.Unlock()
			return nil, nil, errUnavailable
		}
		if o, busy := r.opening[key]; busy {
			r.mu.Unlock()
			select {
			case <-o.done:
				if o.err != nil {
					return nil, nil, o.err
				}
				continue
			case <-ctx.Done():
				return nil, nil, fault.Wrap(fault.FileCancelled, ctx.Err(), "")
			}
		}
		o := &opening{done: make(chan struct{})}
		r.opening[key] = o
		r.mu.Unlock()
		o.err = r.openKind(ctx, p, kind, handle, sourceID, open)
		r.mu.Lock()
		delete(r.opening, key)
		r.mu.Unlock()
		close(o.done)
		if o.err != nil {
			return nil, nil, o.err
		}
	}
}

func (r *Registry) openKind(ctx context.Context, p principal.Principal, kind SourceKind, handle, sourceID string, open Opener) error {
	d, b, err := open(ctx, p, handle)
	if err != nil {
		if _, classified := fault.From(err); !classified {
			err = fault.Wrap(fault.SourceUnavailable, err, "")
		}
		return err
	}
	slot, err := r.Reserve(ctx, p, kind)
	if err != nil {
		_ = b.Close()
		return err
	}
	return slot.add(sourceID, d, b)
}

// hold runs with r.mu held.
func (r *Registry) hold(s *source, p principal.Principal, need Capability) (Backend, func(), error) {
	if s.userID != p.UserID || s.closing || s.closed || !s.backend.Capabilities().Ops.Has(need) {
		return nil, nil, errUnavailable
	}
	s.holds++
	s.lastUsed = r.opts.Now()
	var once sync.Once
	return s.backend, func() { once.Do(func() { r.unhold(s) }) }, nil
}

func (r *Registry) unhold(s *source) {
	r.mu.Lock()
	s.holds--
	s.lastUsed = r.opts.Now()
	last := s.holds == 0 && s.closing
	r.mu.Unlock()
	if last {
		r.finish(s)
	}
}

// Describe returns the descriptor and capabilities of an owned source.
func (r *Registry) Describe(p principal.Principal, sourceID string) (Descriptor, Capabilities, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sources[sourceKey{p.SessionID, sourceID}]
	if !ok || s.userID != p.UserID || s.closing || s.closed {
		return Descriptor{}, Capabilities{}, errUnavailable
	}
	return s.desc, s.backend.Capabilities(), nil
}

// Close ends a Quick SFTP or SMB source of p (file_source_disconnect). A
// held source closes when its last hold ends. Terminal session sources
// and sources of others fail with fault.SourceUnavailable.
func (r *Registry) Close(p principal.Principal, sourceID string) error {
	r.mu.Lock()
	s, ok := r.sources[sourceKey{p.SessionID, sourceID}]
	if !ok || s.userID != p.UserID || s.kind == SourceSFTPSession || s.closing {
		r.mu.Unlock()
		return errUnavailable
	}
	s.closing = true
	now := s.holds == 0
	r.mu.Unlock()
	if now {
		r.finish(s)
	}
	return nil
}

// Revoke closes every source of the revoked browser session, held or not,
// before it returns (K6). Operations still running on them fail with
// fault.SourceUnavailable.
func (r *Registry) Revoke(rev principal.Revocation) {
	r.closeWhere(true, func(s *source) bool {
		if rev.SessionID == "" {
			return s.userID == rev.UserID
		}
		return s.key.session == rev.SessionID
	})
}

// PeerOpened notes a realtime connection of the user (realtime OnOpen);
// PeerClosed forgets it again.
func (r *Registry) PeerOpened(userID int64, peerID uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.peers[userID] == nil {
		r.peers[userID] = map[uint64]bool{}
	}
	r.peers[userID][peerID] = true
}

// PeerClosed forgets a connection; when it was the user's last one,
// the user's quick sources close (LastConnectionClosed).
func (r *Registry) PeerClosed(userID int64, peerID uint64) {
	r.mu.Lock()
	set := r.peers[userID]
	_, known := set[peerID]
	delete(set, peerID)
	last := known && len(set) == 0
	if len(set) == 0 {
		delete(r.peers, userID)
	}
	r.mu.Unlock()
	if last {
		r.LastConnectionClosed(userID)
	}
}

// LastConnectionClosed closes the Quick SFTP and SMB sources of the user,
// deferred while a transfer holds them; terminal session sources stay.
func (r *Registry) LastConnectionClosed(userID int64) {
	r.closeWhere(false, func(s *source) bool { return s.userID == userID && s.kind != SourceSFTPSession })
}

// Sweep closes SMB sources without a hold that were unused for longer than
// the idle limit. cmd/webssh calls it periodically.
func (r *Registry) Sweep() {
	now := r.opts.Now()
	r.closeWhere(false, func(s *source) bool {
		return s.kind == SourceSMBQuick && s.holds == 0 && now.Sub(s.lastUsed) > r.opts.SMBIdle
	})
}

// Shutdown closes every source.
func (r *Registry) Shutdown() { r.closeWhere(true, func(*source) bool { return true }) }

// closeWhere marks the matching sources closing and closes them now
// (force) or when their last hold ends.
func (r *Registry) closeWhere(force bool, match func(*source) bool) {
	var now []*source
	r.mu.Lock()
	for _, s := range r.sources {
		if s.closed || !match(s) {
			continue
		}
		s.closing = true
		if force || s.holds == 0 {
			now = append(now, s)
		}
	}
	r.mu.Unlock()
	for _, s := range now {
		r.finish(s)
	}
}

// finish closes a source once and removes it.
func (r *Registry) finish(s *source) {
	r.mu.Lock()
	if s.closed {
		r.mu.Unlock()
		return
	}
	s.closed = true
	if r.sources[s.key] == s {
		delete(r.sources, s.key)
	}
	hooks := r.onClose
	r.mu.Unlock()
	// A failed close leaves nothing to undo: the source is gone either way.
	_ = s.backend.Close()
	s.quota()
	for _, f := range hooks {
		f(s.key.session, s.key.id)
	}
}
