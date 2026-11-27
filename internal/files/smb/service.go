package smb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json/jsontext"
	"log/slog"
	"regexp"
	"strings"
	"sync"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/principal"
)

// Sources is the file source registry of internal/files: Reserve takes
// the quick-connection quota before the share is dialled, and the slot
// registers the opened source for the user's browser session. The
// registry owns the source from then on: idle expiry, the last realtime
// connection, revocation and the quota.
type Sources interface {
	Reserve(ctx context.Context, p principal.Principal, kind files.SourceKind) (*files.Slot, error)
}

// Passwords resolves a saved password for a connection (internal/vault
// through cmd/webssh). It checks that the credential is assigned to the
// target the page confirmed and returns a fresh copy the caller clears.
type Passwords interface {
	ConnectionPassword(ctx context.Context, p principal.Principal, req CredentialRequest) ([]byte, error)
}

// CredentialRequest names a saved password and the target it is used
// for: the share, or a target the page confirmed with TargetToken.
type CredentialRequest struct {
	CredentialID, TargetToken string
	Target                    ShareFields
}

// Service is the SMB area: saved definitions and connect attempts.
type Service struct {
	Shares    *Shares
	Config    Config
	Sources   Sources
	Passwords Passwords // optional; without it a saved password is unavailable
	Logger    *slog.Logger

	mu       sync.Mutex
	attempts map[attemptKey]context.CancelFunc
}

type attemptKey struct {
	user      int64
	peer      uint64
	requestID string
}

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9:._-]{1,128}$`)

// requestID is _smb_request_id: a valid request_id, else "".
func requestID(v jsontext.Value) string {
	s, ok := jsonString(v)
	if !ok || !requestIDPattern.MatchString(s) {
		return ""
	}
	return s
}

// connectCodes are _SMB_CONNECT_CODES: other failures of a connect are
// reported as CONNECTION_FAILED.
var connectCodes = map[fault.Code]bool{
	fault.SMBAuthenticationRequired: true, fault.SMBConnectionFailed: true, fault.SMBConnectCancelled: true,
	fault.SMBDialectRequired: true, fault.SMBEncryptionRequired: true, fault.SMBIdentityUnavailable: true,
	fault.InvalidRequest: true, fault.FilePermissionDenied: true, fault.SMBQuotaExceeded: true,
	fault.SMBRuntimeShuttingDown: true, fault.ShareUnavailable: true, fault.SourceUnavailable: true,
	fault.SMBTargetNotAllowed: true, fault.FileTimeout: true,
	// Saved-password failures pass with their own codes (credential_error).
	fault.HTTPSRequired: true, fault.VaultLocked: true, fault.VaultMissing: true, fault.CredentialMissing: true,
	fault.AuthenticationNeeded: true, fault.CredentialUnavailable: true, fault.CredentialTargetChanged: true,
	fault.CredentialsDisabled: true,
}

// ConnectRequest is one validated smb.connect.
type ConnectRequest struct {
	RequestID string
	Target    Target
	// CredentialID, when set, replaces Target.Password.
	CredentialID, TargetToken string
}

// begin registers an attempt; a second attempt with the same request on
// the same connection is refused (REQUEST_IN_PROGRESS of today).
func (s *Service) begin(ctx context.Context, key attemptKey) (context.Context, func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.attempts == nil {
		s.attempts = map[attemptKey]context.CancelFunc{}
	}
	if _, busy := s.attempts[key]; busy {
		return nil, nil, fault.New(fault.Busy, "The connection attempt is already in progress.")
	}
	ctx, cancel := context.WithCancel(ctx)
	s.attempts[key] = cancel
	return ctx, func() {
		s.mu.Lock()
		delete(s.attempts, key)
		s.mu.Unlock()
		cancel()
	}, nil
}

// Cancel ends the attempt of requestID of this user on this connection;
// nothing happens when there is none.
func (s *Service) Cancel(user int64, peer uint64, requestID string) {
	s.mu.Lock()
	cancel := s.attempts[attemptKey{user, peer, requestID}]
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// Connect opens the share for the principal's session and registers it as
// a source. live reports whether the realtime connection that asked is
// still there; a source nobody can use any more is closed again.
func (s *Service) Connect(ctx context.Context, p principal.Principal, peer uint64, req ConnectRequest, live func() bool) (files.Descriptor, files.Capabilities, error) {
	ctx, done, err := s.begin(ctx, attemptKey{p.UserID, peer, req.RequestID})
	if err != nil {
		return files.Descriptor{}, files.Capabilities{}, err
	}
	defer done()
	if s.Sources == nil {
		return files.Descriptor{}, files.Capabilities{}, fail(fault.SMBConnectionFailed, PhaseLifecycle, "NoRegistry", nil)
	}
	t := req.Target
	if req.CredentialID != "" {
		if s.Passwords == nil {
			return files.Descriptor{}, files.Capabilities{}, fault.New(fault.CredentialUnavailable, "")
		}
		if err := checkTarget(Target{Host: t.Host, Share: t.Share, Domain: t.Domain, Username: t.Username, Password: []byte{1}}); err != nil {
			return files.Descriptor{}, files.Capabilities{}, err
		}
		pw, err := s.Passwords.ConnectionPassword(ctx, p, CredentialRequest{CredentialID: req.CredentialID, TargetToken: req.TargetToken,
			Target: ShareFields{Host: t.Host, Share: t.Share, Domain: t.Domain, Username: t.Username}})
		if err != nil {
			return files.Descriptor{}, files.Capabilities{}, err
		}
		t.Password = pw
	}
	slot, err := s.Sources.Reserve(ctx, p, files.SourceSMBQuick)
	if err != nil {
		if fault.Is(err, fault.Busy) {
			err = fail(fault.SMBQuotaExceeded, PhaseLifecycle, "QuotaExceeded", err)
		}
		return files.Descriptor{}, files.Capabilities{}, err
	}
	b, err := Connect(ctx, s.Config, t)
	if err != nil {
		slot.Release()
		return files.Descriptor{}, files.Capabilities{}, err
	}
	if ctx.Err() != nil || !live() {
		slot.Release()
		_ = b.Close()
		return files.Descriptor{}, files.Capabilities{}, fail(fault.SMBConnectCancelled, PhaseLifecycle, "Canceled", ctx.Err())
	}
	d := b.Descriptor()
	id, err := slot.Add(d, b)
	if err != nil {
		return files.Descriptor{}, files.Capabilities{}, err
	}
	d.SourceID = id
	return d, b.Capabilities(), nil
}

// connectFailure is the error a failed connect sends: a code of
// _SMB_CONNECT_CODES and a diagnostic id that the server log carries with
// the credential-free diagnostic (SMB-<12 hex>).
func (s *Service) connectFailure(ctx context.Context, p principal.Principal, host, share string, err error) error {
	code := fault.CodeOf(err)
	if !connectCodes[code] {
		code = fault.SMBConnectionFailed
	}
	var token [6]byte
	_, _ = rand.Read(token[:])
	id := "SMB-" + strings.ToUpper(hex.EncodeToString(token[:]))
	d := DiagnosticOf(err)
	s.logger().WarnContext(ctx, "SMB source connection failed", "user_id", p.UserID, "host", host, "share", share,
		"result_code", string(code), "diagnostic_id", id, "diagnostic_phase", string(d.Phase), "cause_type", d.Cause,
		"nt_status", d.NtStatus)
	out := fault.New(code, "")
	if fe, ok := fault.From(err); ok && fe.Code == code {
		out.Message = fe.Message
	}
	out.Details = map[string]any{"diagnostic_id": id}
	return out
}

func (s *Service) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}
