package hosts

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/store"
)

// DetectConn is the authenticated connection of a terminal session to a
// saved host; *client.Conn provides it. The probes run on their own exec
// channels and never touch the interactive shell.
type DetectConn interface {
	Exec(ctx context.Context, command string, stdin io.Reader, stdout, stderr io.Writer) (int, error)
	ServerVersion() string
	Done() <-chan struct{}
}

// Notifier pushes a server event to the account's realtime connections
// (realtime.Server.NotifyUser).
type Notifier func(owner int64, typ string, payload any)

// Detector learns the platform and services of saved hosts from the
// connections users open to them (detect_connected_platform and
// recheck_reboot_hint). The authenticated greeting is read on every
// connection; the identity probe runs at most once a week per saved host,
// and only for hosts whose icon is automatic. Every failure leaves the
// terminal alone.
//
// The probe needs an authenticated connection, so it runs when a user
// connects and not as a periodic job of its own. At most MaxActive
// detections run at once; a connection that finds them all busy is not
// probed this time, and the next connection asks again.
type Detector struct {
	Hosts *Service
	// Describe reads an SSH identification line (hostops.DescribeBanner)
	// and returns the platform it names ("" for none); ok is false when
	// the line is not one.
	Describe  func(line []byte) (platform string, ok bool)
	Notify    Notifier
	Log       *slog.Logger
	MaxActive int
	now       func() time.Time
	timeout   time.Duration // of the identity probe; identityTimeout when zero

	mu      sync.Mutex
	active  int
	closed  bool
	wg      sync.WaitGroup
	pending pendingAttempts
}

// DefaultMaxActive bounds concurrent detections.
const DefaultMaxActive = 8

func (d *Detector) clock() time.Time {
	if d.now != nil {
		return d.now()
	}
	return time.Now()
}

// LoginOf is the login a target makes.
func LoginOf(t client.Target) Login {
	return Login{Host: t.Hop.Host, Port: t.Hop.Port, User: t.Hop.User,
		JumpHostID: t.Display.JumpHostID, SOCKSProxyID: t.Display.SOCKSProxyID}
}

// Connected starts the detection for a new connection to t and returns at
// once. Quick connections have nowhere to keep a result and are left out.
// The work ends with ctx or when conn closes.
func (d *Detector) Connected(ctx context.Context, t client.Target, conn DetectConn) {
	if t.Display.ProfileID == "" || conn == nil {
		return
	}
	limit := d.MaxActive
	if limit <= 0 {
		limit = DefaultMaxActive
	}
	d.mu.Lock()
	if d.closed || d.active >= limit {
		d.mu.Unlock()
		return
	}
	d.active++
	d.wg.Add(1)
	d.mu.Unlock()
	go func() {
		defer func() {
			d.mu.Lock()
			d.active--
			d.mu.Unlock()
			d.wg.Done()
		}()
		rctx, cancel := context.WithCancel(ctx)
		defer cancel()
		go func() {
			select {
			case <-conn.Done():
				cancel()
			case <-rctx.Done():
			}
		}()
		owner, id, login := t.Owner, t.Display.ProfileID, LoginOf(t)
		d.detect(rctx, owner, id, login, conn)
		d.recheckRebootHint(rctx, owner, id, login, conn)
	}()
}

// Shutdown stops new detections and waits for the running ones, which end
// with the context Connected was given.
func (d *Detector) Shutdown(ctx context.Context) error {
	d.mu.Lock()
	d.closed = true
	d.mu.Unlock()
	done := make(chan struct{})
	go func() { d.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *Detector) logger() *slog.Logger {
	if d.Log != nil {
		return d.Log
	}
	return slog.Default()
}

func (d *Detector) notify(owner int64, typ string, payload any) {
	if d.Notify != nil {
		d.Notify(owner, typ, payload)
	}
}

// profile reads the saved host id of owner, if it has the login.
func (s *Service) profile(ctx context.Context, owner int64, id string, ep Login) (*record, error) {
	var out *record
	key := ep.key()
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		profiles, err := load(ctx, tx, profileTable, owner)
		if err != nil {
			return err
		}
		if i := find(profiles, id); i >= 0 && key != "" && endpointOf(&profiles[i]) == key {
			r := profiles[i].clone()
			out = &r
		}
		return nil
	})
	return out, err
}

// greeting is _connection_greeting: the platform the connection's version
// string names ("" for none); ok is false without a usable one.
func (d *Detector) greeting(conn DetectConn) (string, bool) {
	version := conn.ServerVersion()
	if d.Describe == nil || len(version) < 4 || version[:4] != "SSH-" {
		return "", false
	}
	return d.Describe([]byte(version))
}

func (d *Detector) detect(ctx context.Context, owner int64, id string, ep Login, conn DetectConn) {
	r, err := d.Hosts.profile(ctx, owner, id, ep)
	if err != nil || r == nil {
		if err != nil {
			d.logger().DebugContext(ctx, "host identity detection skipped", "error", err)
		}
		return
	}
	if platform, ok := d.greeting(conn); ok {
		stored, _ := r.str("greeting_platform")
		authenticated, hasAuthenticated := r.str("authenticated_greeting")
		if nonPOSIXPlatforms[platform] || platform != stored || !hasAuthenticated || authenticated != platform {
			updated, changed, err := d.Hosts.RecordConnectGreeting(ctx, owner, id, ep, platform, d.clock())
			if err != nil {
				d.logger().DebugContext(ctx, "connection greeting not stored", "error", err)
			}
			if nonPOSIXPlatforms[platform] {
				// No POSIX shell to run the probe in.
				if changed {
					d.notify(owner, protocol.TypeDiscoveryPlatform, protocol.DiscoveryPlatform{ProfileID: id})
				}
				return
			}
			if updated != nil {
				if u, err := parseRecord(updated); err == nil {
					r = &u
				}
			}
		}
	}
	if !identityNeeded(r, d.clock()) {
		return
	}
	attempt := pendingKey{owner: owner, id: id, login: ep.key()}
	if d.pending.due(attempt, d.clock()) {
		return
	}
	d.probe(ctx, owner, id, ep, conn, attempt)
}

// probe runs the identity probe and stores what it found.
func (d *Detector) probe(ctx context.Context, owner int64, id string, ep Login, conn DetectConn, attempt pendingKey) {
	timeout := d.timeout
	if timeout == 0 {
		timeout = identityTimeout
	}
	identity, answer := collectIdentity(ctx, conn, timeout)
	checked := d.clock()
	// Silence may be a slow shell start and a stall a hung mount; both are
	// asked again after a day by recording the check as that much older.
	// So is any failure once the command was sent: it may have run.
	retry := checked.Add(-(IdentityRefresh - SilentRetry))
	var result *Identity
	switch answer {
	case answerUnsupported, answerSilent:
		// The host answered, but not with the probe's output: a forced
		// command, a menu or a shell without the tools. Asking again on
		// every login would only run that command again.
		result = &Identity{State: StateUnavailable, Services: []string{}}
		if answer == answerSilent {
			checked = retry
		}
	case "":
		result = &identity
	default:
		checked = retry
	}
	if ctx.Err() != nil {
		result, checked = nil, minTime(checked, retry)
	}
	if result == nil {
		d.recordAttempt(ctx, owner, id, ep, attempt, checked)
		return
	}
	stored, err := d.Hosts.CacheIdentity(context.WithoutCancel(ctx), owner, id, ep, *result, checked, answer == answerSilent)
	if err != nil && !isQuota(err) {
		d.logger().WarnContext(ctx, "detected host facts could not be saved", "profile_id", id, "error", err)
	}
	if !stored {
		d.recordAttempt(ctx, owner, id, ep, attempt, minTime(checked, retry))
		return
	}
	if result.State != StateDetected {
		// The saved host shows at once that detection is not possible.
		d.notify(owner, protocol.TypeDiscoveryPlatform, protocol.DiscoveryPlatform{ProfileID: id})
		return
	}
	wire := identityWire(*result)
	d.notify(owner, protocol.TypeDiscoveryPlatform, protocol.DiscoveryPlatform{
		ProfileID: id, Platform: result.Platform, Services: wire.Services, Identity: &wire})
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// recordAttempt stores when the probe ran; where the store refuses, the
// attempt is kept in memory until the probe is due again.
func (d *Detector) recordAttempt(ctx context.Context, owner int64, id string, ep Login, attempt pendingKey, at time.Time) {
	ok, err := d.Hosts.RecordIdentityAttempt(context.WithoutCancel(ctx), owner, id, ep, at)
	if err != nil {
		d.logger().DebugContext(ctx, "host identity attempt could not be saved", "profile_id", id, "error", err)
	}
	if !ok {
		d.pending.remember(attempt, at.Add(IdentityRefresh), d.clock())
	}
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func identityWire(id Identity) protocol.DiscoveryIdentity {
	services := append([]string{}, id.Services...)
	return protocol.DiscoveryIdentity{State: id.State, Platform: optional(id.Platform), Family: optional(id.Family),
		OSID: optional(id.OSID), OSVersion: optional(id.OSVersion), Virt: optional(id.Virt), Graphical: id.Graphical,
		Guests: id.Guests, Services: services, ContainerAccess: optional(id.ContainerAccess)}
}

// recheckRebootHint is recheck_reboot_hint: while the overview shows a
// restart hint from a check the user ran, the restart marker alone is
// reread on login. Exactly "reboot=no" lowers the hint, exactly
// "reboot=yes" keeps it; any other answer may come from a forced command
// that the server runs in place of ours, so the recheck stops for this
// hint until the next full check.
func (d *Detector) recheckRebootHint(ctx context.Context, owner int64, id string, ep Login, conn DetectConn) {
	if ctx.Err() != nil {
		return
	}
	r, err := d.Hosts.profile(ctx, owner, id, ep)
	if err != nil || r == nil {
		return
	}
	checkedAt, due := rebootHintNeedsCheck(r, d.clock())
	if !due {
		return
	}
	reboot, err := collectRebootHint(ctx, conn)
	if ctx.Err() != nil || (err == nil && reboot) {
		return
	}
	settled, serr := d.Hosts.SettleRebootHint(context.WithoutCancel(ctx), owner, id, ep, checkedAt, err == nil)
	if serr != nil {
		d.logger().DebugContext(ctx, "host restart hint not settled", "profile_id", id, "error", serr)
	}
	if settled && err == nil {
		d.notify(owner, protocol.TypeDiscoveryMaintenance, protocol.DiscoveryMaintenance{ProfileID: id})
	}
}

// pendingAttempts are probe attempts the store refused to record:
// (owner, host, login) -> time the probe is due. The map is per process
// and bounded; it is lost on a restart.
type pendingAttempts struct {
	mu sync.Mutex
	m  map[pendingKey]time.Time
}

type pendingKey struct {
	owner int64
	id    string
	login string
}

const pendingLimit = 4096

func (p *pendingAttempts) remember(k pendingKey, due, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.m == nil {
		p.m = map[pendingKey]time.Time{}
	}
	for key, until := range p.m {
		if !until.After(now) {
			delete(p.m, key)
		}
	}
	delete(p.m, k)
	for key := range p.m {
		if len(p.m) < pendingLimit {
			break
		}
		delete(p.m, key)
	}
	p.m[k] = due
}

func (p *pendingAttempts) due(k pendingKey, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	until, ok := p.m[k]
	return ok && now.Before(until)
}
