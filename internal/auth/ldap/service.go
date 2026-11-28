package ldap

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
)

// Feature is the security feature of LDAP sign-in (operations.Gates).
const Feature = "ldap"

// Service is LDAP sign-in for one directory (LDAP_PROVIDER_ID). With
// Enabled false it only keeps LDAP-managed accounts out: their sessions
// end at the next request, as in the Python release.
type Service struct {
	DB *store.DB
	// Directory is the LDAP server; nil when LDAP_ENABLED is false.
	Directory Directory
	Accounts  Accounts
	Sessions  Sessions
	StepUp    StepUp
	Passwords Passwords
	// OIDC removes OIDC identities when an account becomes LDAP-managed;
	// nil removes nothing.
	OIDC  Identities
	Gates Gates
	Audit Auditor
	// Admins reports names listed in ADMIN_USERS; their identity cannot
	// be unlinked.
	Admins func(username string) bool
	// Attempts reserves one sign-in attempt for the directory entry
	// (provider and subject) before its password is checked, so the
	// ceiling per name holds whatever spelling of the name the directory
	// matched (auth.Flow.ReserveSubjectAttempt). release is called after a
	// successful sign-in; nil reserves nothing.
	Attempts func(ctx context.Context, subject string) (release func(), ok bool)

	Enabled       bool
	Provider      string        // LDAP_PROVIDER_ID
	AutoProvision bool          // LDAP_AUTO_PROVISION
	Revalidation  time.Duration // LDAP_SESSION_REVALIDATION_SECONDS
	Logger        *slog.Logger
	Now           func() time.Time

	mu       sync.Mutex
	checking map[int64]bool
}

var _ auth.Provider = (*Service)(nil)

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

func (s *Service) audit(event string, kv ...any) {
	if s.Audit != nil {
		s.Audit.Security(event, kv...)
	}
}

// active reports whether LDAP sign-in is on: configured and the security
// feature active. A failing gate counts as off (fail closed).
func (s *Service) active(ctx context.Context) bool {
	if !s.Enabled || s.Directory == nil {
		return false
	}
	if s.Gates == nil {
		return true
	}
	on, err := s.Gates.Active(ctx, Feature)
	return err == nil && on
}

// Errors of the sign-in and administration, without directory detail.
var (
	errAuthFailed  = fault.New(fault.AuthFailed, "Invalid username or password")
	errUnavailable = fault.New(fault.Unavailable, "Directory sign-in is temporarily unavailable")
	errTooMany     = fault.New(fault.RateLimited, "Too many login attempts")
)

// classify turns a directory error into the fault the routes answer:
// ErrRejected is a refusal, everything else an unavailable directory.
func classify(err error, unavailable error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrRejected):
		return errAuthFailed
	case fault.Is(err, fault.AuthFailed):
		return err
	}
	return fault.Wrap(fault.Unavailable, err, messageOf(unavailable))
}

func messageOf(err error) string {
	if fe, ok := fault.From(err); ok {
		return fe.Message
	}
	return ""
}

// Name implements auth.Provider; it is the sign-in method recorded in
// the session ("ldap").
func (*Service) Name() string { return string(auth.ProviderLDAP) }

// IdentityOf returns the LDAP identity of an account, or found false.
func (s *Service) IdentityOf(ctx context.Context, userID int64) (Identity, bool, error) {
	var id Identity
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		id, err = identityOfTx(ctx, tx, userID)
		return err
	})
	if errors.Is(err, errNoIdentity) {
		return Identity{}, false, nil
	}
	if err != nil {
		return Identity{}, false, fault.Wrap(fault.StorageError, err, "")
	}
	return id, true, nil
}

// pyStrip is Python's str.strip().
func pyStrip(s string) string { return strings.TrimFunc(s, pyIsSpace) }
