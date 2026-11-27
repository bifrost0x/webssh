package transfer

import (
	"context"
	"crypto/sha256"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
)

// Quota kinds a transfer reserves (internal/quota).
const (
	quotaTransfer = "transfer"
	quotaTemp     = "temp_bytes"
	quotaJob      = "background_job"
)

// Audit records transfers (internal/audit).
type Audit interface {
	Security(event string, kv ...any)
}

// Options configure a Manager. Sources, Quotas and Events are required.
type Options struct {
	Sources Sources
	Quotas  Quotas
	Events  Events
	// Describe, when set, names the endpoints of a source in the audit
	// record; Audit, when set, receives FILE_SOURCE_OPERATION.
	Describe func(userID int64, session, sourceID string) (files.Descriptor, bool)
	Audit    Audit
	// Charge, when set, takes the bytes of a realtime request from the
	// user's budget of file requests (files.Service.ChargeRequest).
	Charge func(userID int64, n int) error
	Limits Limits
	// BasePath is APPLICATION_ROOT without a trailing slash; the URLs of
	// prepared transfers start with it.
	BasePath string
	Logger   *slog.Logger
	Now      func() time.Time
	// ChunkSize is the size of one read (CHUNK_SIZE, 64 KiB).
	ChunkSize int
	// IdleTimeout bounds one read from or write to the browser of a
	// running HTTP transfer.
	IdleTimeout time.Duration
	// TokenTTL is how long a prepared transfer waits for its request
	// (TokenTTL when 0).
	TokenTTL time.Duration
}

// principalKey is the owner of a transfer: the user and the browser session.
type principalKey struct {
	userID  int64
	session string
}

// record is one transfer from preparation to its final state.
type record struct {
	id        string
	token     [32]byte // SHA-256 of the token while pending, zero after
	owner     principalKey
	peer      uint64 // the realtime connection that prepared it
	direction Direction
	archive   bool
	sourceID  string
	path      string
	policy    ConflictPolicy
	copy      *CopyRef
	destID    string
	destPath  string

	state   State
	started time.Time
	expiry  *time.Timer
	cancel  context.CancelCauseFunc // set while running
	release []func()                // quota and source holds, run once at the end
	done    chan struct{}           // closed in the final state
}

// http reports whether r is an HTTP upload or download.
func (r *record) http() bool { return r.direction != ServerToServer }

// terminal is what stays of a finished transfer for a while, so a late
// cancel learns its final state.
type terminal struct {
	userID int64
	state  State
	until  time.Time
}

// maxTerminal bounds the remembered final states.
const maxTerminal = 4096

// Manager owns the transfers of every user: one-use tokens, quota, source
// holds, cancellation and the host-to-host copies running in the
// background.
type Manager struct {
	o Options

	mu       sync.Mutex
	records  map[string]*record
	tokens   map[[32]byte]*record
	terminal map[string]terminal
	peers    map[int64]map[uint64]bool
	closed   bool
	base     context.Context // ends at Shutdown
	stop     context.CancelFunc

	work sync.WaitGroup // copies and running HTTP transfers
}

// Defaults of Options.
const (
	DefaultChunkSize   = 64 << 10
	DefaultIdleTimeout = 2 * time.Minute
)

// New returns a manager.
func New(o Options) *Manager {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.ChunkSize <= 0 {
		o.ChunkSize = DefaultChunkSize
	}
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = DefaultIdleTimeout
	}
	if o.TokenTTL <= 0 {
		o.TokenTTL = TokenTTL
	}
	if o.Limits == (Limits{}) {
		o.Limits = DefaultLimits
	}
	base, stop := context.WithCancel(context.Background())
	return &Manager{
		o: o, records: map[string]*record{}, tokens: map[[32]byte]*record{},
		terminal: map[string]terminal{}, peers: map[int64]map[uint64]bool{}, base: base, stop: stop,
	}
}

func tokenKey(token string) [32]byte { return sha256.Sum256([]byte(token)) }

// create registers a pending transfer. It takes ownership of release: on
// failure it runs at once. The transfer quota is reserved here.
func (m *Manager) create(ctx context.Context, r *record, release []func()) (string, error) {
	fail := func(err error) (string, error) {
		runAll(release)
		return "", err
	}
	quota, err := m.o.Quotas.Reserve(ctx, quotaTransfer, r.owner.userID, 1)
	if err != nil {
		return fail(err)
	}
	release = append(release, quota)
	r.release = release
	token := NewToken()
	r.id = newID()
	r.state = Pending
	r.started = m.o.Now()
	r.done = make(chan struct{})
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return fail(fault.New(fault.Unavailable, ""))
	}
	m.records[r.id] = r
	if r.direction == ServerToServer {
		r.state = Running
	} else {
		r.token = tokenKey(token)
		m.tokens[r.token] = r
		r.expiry = time.AfterFunc(m.o.TokenTTL, func() { m.expire(r) })
	}
	m.mu.Unlock()
	return token, nil
}

// newID is a transfer id (secrets.token_urlsafe(18) in Python).
func newID() string { return NewToken()[:24] }

func runAll(fs []func()) {
	for _, f := range slices.Backward(fs) {
		f()
	}
}

// expire ends a token that was not used in time.
func (m *Manager) expire(r *record) {
	m.mu.Lock()
	pending := r.state == Pending
	m.mu.Unlock()
	if pending {
		m.finish(r, Failed, nil, false)
	}
}

// finish moves r to its final state once and releases what it holds. It
// reports false when r was final already. With notify the user's
// connections learn the outcome.
func (m *Manager) finish(r *record, state State, f *Failure, notify bool) bool {
	now := m.o.Now()
	m.mu.Lock()
	if r.state.Terminal() {
		m.mu.Unlock()
		return false
	}
	r.state = state
	delete(m.records, r.id)
	if r.token != ([32]byte{}) {
		delete(m.tokens, r.token)
		r.token = [32]byte{}
	}
	if r.expiry != nil {
		r.expiry.Stop()
	}
	m.rememberLocked(r.id, terminal{userID: r.owner.userID, state: state, until: now.Add(m.o.TokenTTL)}, now)
	release := r.release
	r.release = nil
	close(r.done)
	m.mu.Unlock()
	runAll(release)
	if notify {
		ev := Finished{TransferID: r.id, Direction: r.direction, State: state, Failure: f, Copy: r.copy}
		if r.copy != nil {
			ev.Filename, ev.SourcePath, ev.DestPath = baseName(r.path), r.path, r.destPath
		}
		m.o.Events.Finished(r.owner.userID, ev)
	}
	return true
}

func (m *Manager) rememberLocked(id string, t terminal, now time.Time) {
	if len(m.terminal) >= maxTerminal {
		for k, v := range m.terminal {
			if !now.Before(v.until) || len(m.terminal) >= maxTerminal {
				delete(m.terminal, k)
			}
		}
	}
	m.terminal[id] = t
}
