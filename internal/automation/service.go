package automation

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/vault"
)

// Records returns the stored saved hosts and jump hosts of a user, the
// records saved passwords are bound to (the vault's Stores).
type Records interface {
	Records(ctx context.Context, userID int64) (vault.Records, error)
}

// Passwords reads saved passwords (internal/vault).
type Passwords interface {
	// Password returns the secret assigned to the resource when t is the
	// target it was confirmed for; the caller clears it after use.
	Password(ctx context.Context, userID int64, resourceID string, t vault.Target) ([]byte, error)
	// Binding is the state of the assignment for t and, when it is ready,
	// a token that changes with every new assignment, replaced password
	// and change of the saved-password switch.
	Binding(ctx context.Context, userID int64, resourceID string, t vault.Target) (vault.Status, string, error)
}

// Keys reads the stored SSH keys (internal/vault): the public key, in
// SSH wire form, of a key the user can sign in with.
type Keys interface {
	PublicKey(ctx context.Context, owner int64, keyID string) ([]byte, error)
}

// HostTrust reports whether a host already has a trusted host key for
// the user (internal/ssh/hostkey). Automation never accepts a new key.
type HostTrust interface {
	Trusted(ctx context.Context, owner int64, host string, port int) (bool, error)
}

// Resolver returns the connection target of a saved host
// (internal/hosts).
type Resolver interface {
	Resolve(ctx context.Context, owner int64, profileID string) (client.Target, error)
}

// Conn is an open SSH connection of a run.
type Conn interface {
	Executor
	Close() error
}

// Dialer opens a connection through the shared dialer; a run passes
// Unattended, so a host key without trust is refused.
type Dialer interface {
	Dial(ctx context.Context, t client.Target, ix client.Interaction) (Conn, error)
}

// Switches reads the administrator switches; an error counts as off.
type Switches interface {
	AutomationEnabled(ctx context.Context) (bool, error)
	CredentialsEnabled(ctx context.Context) (bool, error)
}

// Quotas reserves runtime quotas (internal/quota).
type Quotas interface {
	Reserve(ctx context.Context, kind string, userID, amount int64) (release func(), err error)
}

// StepUp consumes account step-up grants (internal/auth/stepup).
type StepUp interface {
	Consume(ctx context.Context, p principal.Principal, action principal.Action, target, grant string) error
}

// Auditor writes security events (internal/audit).
type Auditor interface {
	Security(event string, kv ...any)
}

// Facts receives the outcome of every step that ran, so the host's
// maintenance facts follow a run of the read-only maintenance check
// (_record_maintenance_facts). Errors are ignored by the caller.
type Facts interface {
	StepFinished(ctx context.Context, owner int64, profileID string, login Login, step Step, r StepResult) error
}

// Login is the endpoint a run used for a host.
type Login struct {
	Host       string
	Port       int
	User       string
	JumpHostID string
}

// Options are the dependencies of the service. Facts and Audit may be
// nil.
type Options struct {
	DB        *store.DB
	Records   Records
	Passwords Passwords
	Keys      Keys
	HostTrust HostTrust
	Resolver  Resolver
	Dialer    Dialer
	Switches  Switches
	Quotas    Quotas
	StepUp    StepUp
	Audit     Auditor
	Facts     Facts
	// Accepting reports whether the server takes new work (not draining,
	// not in maintenance).
	Accepting func() bool
	Logger    *slog.Logger
	Now       func() time.Time
}

// Service is the automation capability.
type Service struct {
	o       Options
	intents intents

	mu       sync.Mutex
	active   map[int64]*active
	stopping bool
	sched    ScheduleRuns
	work     sync.WaitGroup
}

// maxActiveRuns bounds the runs of all users; each user has at most one.
const maxActiveRuns = 4

// New checks the options and returns the service.
func New(o Options) (*Service, error) {
	if o.DB == nil || o.Records == nil || o.Passwords == nil || o.Keys == nil || o.HostTrust == nil ||
		o.Resolver == nil || o.Dialer == nil || o.Switches == nil || o.Quotas == nil || o.StepUp == nil {
		return nil, errors.New("automation: incomplete options")
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Accepting == nil {
		o.Accepting = func() bool { return true }
	}
	return &Service{o: o, active: map[int64]*active{}}, nil
}

func (s *Service) audit(event string, kv ...any) {
	if s.o.Audit != nil {
		s.o.Audit.Security(event, kv...)
	}
}

// Sweep drops expired reviews (the cleanup loop).
func (s *Service) Sweep() {
	now := s.o.Now()
	s.intents.drop(func(r *review) bool { return !r.expires.After(now) })
}

// Revoked stops the runs of a revoked sign-in and drops its reviews
// (revoke_session); a revocation without a session ends all of the
// user's (revoke).
func (s *Service) Revoked(rev principal.Revocation) {
	s.intents.drop(func(r *review) bool {
		return r.userID == rev.UserID && (rev.SessionID == "" || r.sessionID == rev.SessionID)
	})
	s.mu.Lock()
	a := s.active[rev.UserID]
	s.mu.Unlock()
	if a != nil && a.scheduleID == "" && (rev.SessionID == "" || a.sessionID == rev.SessionID) {
		a.stop()
	}
}

// Shutdown stops new runs, cancels the running ones and waits for them
// to record their outcome or for ctx to end.
func (s *Service) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.stopping = true
	for _, a := range s.active {
		a.stop()
	}
	s.mu.Unlock()
	s.intents.drop(func(*review) bool { return true })
	done := make(chan struct{})
	go func() { s.work.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
