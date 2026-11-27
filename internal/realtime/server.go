package realtime

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// Config holds the limits of the endpoint. Zero values take the defaults.
type Config struct {
	// CookieName is the session cookie (SESSION_COOKIE_NAME, default
	// "session").
	CookieName string
	// MaxConns bounds open connections of the process
	// (MAX_SOCKET_CONNECTIONS; default 1024).
	MaxConns int
	// MaxConnsPerUser bounds open connections of one user
	// (MAX_SOCKET_CONNECTIONS_PER_USER; default 32).
	MaxConnsPerUser int
	// ReadLimit is the largest message a client may send. The endpoint
	// raises it to fit the largest mounted payload; the default fits a
	// binary input frame of 128 KiB.
	ReadLimit int64
	// QueueLen bounds outbound messages per connection (default 512).
	QueueLen int
	// QueueBytes bounds outbound bytes per connection (default 8 MiB). It
	// sits above the terminal's own per-connection output window, so that
	// only a client that stopped reading reaches it.
	QueueBytes int64
	// WriteTimeout bounds one WebSocket write and the pong after a ping
	// (default 10 s).
	WriteTimeout time.Duration
	// PingInterval is the keepalive (default 25 s, as Socket.IO).
	PingInterval time.Duration
	// RecheckInterval is the backstop re-validation of the session for
	// expiry (default 30 s). Revocations do not wait for it.
	RecheckInterval time.Duration
	// InflightPerConn bounds concurrent async requests (default 16).
	InflightPerConn int
	// RejectSlots bounds connections that are accepted only to be closed
	// with a readable reason when a connection limit is reached (default
	// 64). Beyond it the upgrade is refused with plain HTTP 503.
	RejectSlots int
}

// Defaults of Config.
const (
	DefaultCookieName      = "session"
	DefaultMaxConns        = 1024
	DefaultMaxConnsPerUser = 32
	DefaultReadLimit       = 128<<10 + protocol.HeaderLen
	DefaultQueueLen        = 512
	DefaultQueueBytes      = 8 << 20
	DefaultWriteTimeout    = 10 * time.Second
	DefaultPingInterval    = 25 * time.Second
	DefaultRecheckInterval = 30 * time.Second
	DefaultInflightPerConn = 16
	DefaultRejectSlots     = 64
)

// envelopeOverhead is added to the largest payload for the read limit:
// version, type, id and member names.
const envelopeOverhead = 512

func (c *Config) defaults() {
	def := func(v *int, d int) {
		if *v <= 0 {
			*v = d
		}
	}
	defD := func(v *time.Duration, d time.Duration) {
		if *v <= 0 {
			*v = d
		}
	}
	if c.CookieName == "" {
		c.CookieName = DefaultCookieName
	}
	def(&c.MaxConns, DefaultMaxConns)
	def(&c.MaxConnsPerUser, DefaultMaxConnsPerUser)
	c.MaxConnsPerUser = min(c.MaxConnsPerUser, c.MaxConns)
	def(&c.QueueLen, DefaultQueueLen)
	def(&c.InflightPerConn, DefaultInflightPerConn)
	def(&c.RejectSlots, DefaultRejectSlots)
	if c.ReadLimit <= 0 {
		c.ReadLimit = DefaultReadLimit
	}
	if c.QueueBytes <= 0 {
		c.QueueBytes = DefaultQueueBytes
	}
	defD(&c.WriteTimeout, DefaultWriteTimeout)
	defD(&c.PingInterval, DefaultPingInterval)
	defD(&c.RecheckInterval, DefaultRecheckInterval)
}

// Deps are the collaborators of the endpoint. Origin, Sessions,
// Revocations and Log are required.
type Deps struct {
	Origin      *OriginPolicy
	Sessions    SessionValidator
	Revocations Revocations
	Limiter     Limiter // optional: no rate limits
	Auditor     Auditor // optional: no audit records
	Log         *slog.Logger
}

// Restorer lists the terminal sessions a new connection of p may attach
// to and the persistent sessions it may reconnect; both are sent in hello
// (provided by internal/terminal).
type Restorer interface {
	Restorable(ctx context.Context, p principal.Principal) ([]protocol.SessionInfo, error)
	Persistent(ctx context.Context, p principal.Principal) ([]protocol.SessionInfo, error)
}

// BinaryHandler receives every binary frame of a connection. It runs on
// the read loop and must not block; a returned error closes the
// connection with protocol.CloseProtocolViolation. The read loop drops
// frames once the connection began to close; a frame read just before a
// revocation can still arrive, so a handler that forwards input checks
// peer.Context() where it hands the bytes on (condition K6).
type BinaryHandler func(peer protocol.Peer, frame []byte) error

// Server is the http.Handler of GET /ws.
type Server struct {
	cfg  Config
	deps Deps
	log  *slog.Logger

	reg      registry
	binary   BinaryHandler
	restorer Restorer
	onOpen   []func(protocol.Peer)
	onClose  []func(protocol.Peer)
	frozen   atomic.Bool
	freezing sync.Once

	readLimit       int64
	cap             *capacity
	rejectSlots     chan struct{}
	sessions        *sessionIndex
	unsubscribe     func()
	unsubscribeOnce sync.Once

	// mu orders admissions against Shutdown, so that no connection
	// joins conns after Shutdown started waiting.
	mu       sync.Mutex
	shutdown atomic.Bool
	conns    sync.WaitGroup

	lastOriginLog atomic.Int64
}

// NewServer validates the origin policy, subscribes to revocations and
// returns the endpoint. Close the subscription with Shutdown.
func NewServer(cfg Config, deps Deps) (*Server, error) {
	if deps.Origin == nil || deps.Sessions == nil || deps.Revocations == nil || deps.Log == nil {
		return nil, errors.New("realtime: origin policy, sessions, revocations and logger are required")
	}
	ignored, err := deps.Origin.Compile()
	if err != nil {
		return nil, err
	}
	cfg.defaults()
	s := &Server{
		cfg: cfg, deps: deps, log: deps.Log,
		reg:         registry{routes: map[string]protocol.Route{}},
		cap:         newCapacity(cfg.MaxConns, cfg.MaxConnsPerUser),
		rejectSlots: make(chan struct{}, cfg.RejectSlots),
		sessions:    newSessionIndex(),
	}
	switch {
	case deps.Origin.AllowAny:
		s.log.Warn("realtime connections accept any origin (SOCKETIO_ALLOW_ANY_ORIGIN); use it only for a front end served from another origin")
	case deps.Origin.IgnoreScheme:
		s.log.Warn("realtime connections compare the origin without its scheme, as kept from the previous release; configure trusted proxies to restore the full check")
	}
	for _, o := range ignored {
		s.log.Warn("CORS_ORIGINS entry is not an origin and never matches; it is ignored", "entry", truncate(o, 200))
	}
	s.Mount(s.keepaliveRoute())
	s.unsubscribe = deps.Revocations.Subscribe(s.revoke)
	return s, nil
}

// HandleBinary installs the binary fast path (one owner: the terminal).
func (s *Server) HandleBinary(h BinaryHandler) {
	s.mustNotServe()
	s.binary = h
}

// SetRestorer installs the source of hello's restorable sessions.
func (s *Server) SetRestorer(r Restorer) {
	s.mustNotServe()
	s.restorer = r
}

// OnOpen registers f, called once per connection before it handles its
// first frame. Every connection that ran it also runs the OnClose hooks.
func (s *Server) OnOpen(f func(protocol.Peer)) {
	s.mustNotServe()
	s.onOpen = append(s.onOpen, f)
}

// OnClose registers cleanup that runs once per connection after it ended
// and all its handlers returned.
func (s *Server) OnClose(f func(protocol.Peer)) {
	s.mustNotServe()
	s.onClose = append(s.onClose, f)
}

// mustNotServe panics on registrations after the first upgrade: wiring
// happens before the listener starts.
func (s *Server) mustNotServe() {
	if s.frozen.Load() {
		panic("realtime: registration after the endpoint started serving")
	}
}

// freeze fixes the registrations and the read limit before the first
// upgrade; concurrent first requests wait until it is done.
func (s *Server) freeze() {
	s.freezing.Do(func() {
		s.readLimit = max(s.cfg.ReadLimit, int64(s.reg.maxPayload)+envelopeOverhead)
		s.frozen.Store(true)
	})
}

// ServeHTTP checks origin, session and capacity, in this order, and then
// upgrades. Refusals before the upgrade are plain HTTP; after it the page
// can read a close code and reason.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.freeze()
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.shutdown.Load() {
		http.Error(w, "the server is shutting down", http.StatusServiceUnavailable)
		return
	}
	if err := s.deps.Origin.Check(r); err != nil {
		s.logOriginRefusal(r, err)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	p, ok := s.authenticate(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if p.Recovery {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if hit := s.cap.acquire(p.UserID); hit != limitNone {
		s.refuseOverLimit(w, r, hit)
		return
	}
	defer s.cap.release(p.UserID)

	ws, raw, ok := s.accept(w, r)
	if !ok {
		return
	}
	if !s.admit() {
		closeBounded(ws, raw, protocol.CloseMaintenance, "the server is shutting down")
		return
	}
	defer s.conns.Done()
	newConn(s, ws, raw, p).run(r.Context())
}

func (s *Server) authenticate(r *http.Request) (principal.Principal, bool) {
	c, err := r.Cookie(s.cfg.CookieName)
	if err != nil || c.Value == "" {
		return principal.Principal{}, false
	}
	p, err := s.deps.Sessions.Authenticate(r.Context(), c.Value)
	if err != nil || !p.Valid() {
		return principal.Principal{}, false
	}
	return p, true
}

// acceptOptions is the one configuration of the WebSocket library.
//
// InsecureSkipVerify turns off the library's own origin check, which
// accepts a missing Origin and ignores the scheme (K6). OriginPolicy has
// already decided before this point. No other file may set the field
// (architecture test). Compression stays off: secrets and attacker
// influenced bytes share frames (CRIME/BREACH class), and it costs memory
// per connection.
func acceptOptions(subprotocols []string) *websocket.AcceptOptions {
	return &websocket.AcceptOptions{
		Subprotocols:       subprotocols,
		InsecureSkipVerify: true,
		CompressionMode:    websocket.CompressionDisabled,
	}
}

// accept upgrades and negotiates the schema version. Without a common
// version the connection is accepted and closed with 4001, which the page
// can read, unlike a refused HTTP response.
func (s *Server) accept(w http.ResponseWriter, r *http.Request) (*websocket.Conn, net.Conn, bool) {
	var offer []string
	if v := pickVersion(r); v > 0 {
		offer = []string{protocol.Subprotocol(v)}
	}
	ws, raw, err := upgrade(w, r, offer)
	if err != nil {
		return nil, nil, false // Accept has written the HTTP error
	}
	ws.SetReadLimit(s.readLimit)
	if ws.Subprotocol() == "" {
		closeBounded(ws, raw, protocol.CloseUnsupportedVersion, "supported: "+protocol.Subprotocol(protocol.Version))
		return nil, nil, false
	}
	return ws, raw, true
}

func (s *Server) logOriginRefusal(r *http.Request, err error) {
	now := time.Now().Unix()
	last := s.lastOriginLog.Load()
	if now-last < 60 || !s.lastOriginLog.CompareAndSwap(last, now) {
		return
	}
	s.log.Warn("realtime upgrade refused", "reason", err.Error(),
		"origin", truncate(r.Header.Get("Origin"), 200), "host", truncate(r.Host, 200))
}

// admit counts an upgraded connection unless Shutdown has begun.
func (s *Server) admit() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.shutdown.Load() {
		return false
	}
	s.conns.Add(1)
	return true
}

// Shutdown refuses new upgrades and closes every connection with
// protocol.CloseMaintenance. A connection admitted but not yet registered
// sees the flag after its registration and closes itself (Conn.run). It
// waits until all connections have finished or ctx ends, and ends the
// revocation subscription once they have.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.shutdown.Store(true)
	s.mu.Unlock()
	for _, c := range s.sessions.all() {
		c.closeWith(protocol.CloseMaintenance, "the server is shutting down")
	}
	done := make(chan struct{})
	go func() {
		s.conns.Wait()
		close(done)
	}()
	select {
	case <-done:
		s.unsubscribeOnce.Do(s.unsubscribe)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Stats is a snapshot for diagnostics.
type Stats struct{ Conns int }

// Stats returns the number of open connections.
func (s *Server) Stats() Stats { return Stats{Conns: s.cap.open()} }
