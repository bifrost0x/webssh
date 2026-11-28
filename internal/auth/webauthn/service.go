// Package webauthn is the passkey factor: registration of discoverable
// credentials, sign-in without a user name, the passkey as second factor
// and as step-up proof, and the passkey switch for MFA. The ceremony
// checks follow W3C Web Authentication Level 3 and are implemented here
// with the standard library (strict CBOR, COSE ES256, RS256 and EdDSA,
// attestation none and packed). RP ID and origin come unchanged from the
// configuration, the user handle is the account id in ASCII decimal, and
// the signature counter rule is that of the Python release, so migrated
// passkeys keep working.
package webauthn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// Limits of app/webauthn_routes.py.
const (
	MaxPasskeys      = 10 // _AUTHENTICATION_DESCRIPTOR_COUNT
	MaxNameChars     = 80
	DefaultName      = "Passkey"
	minCeremonyChars = 16
	maxCeremonyChars = 256
)

// Service is the passkey factor of the accounts in DB.
type Service struct {
	DB       *store.DB
	Ring     *keyring.Ring
	RP       RelyingParty
	MFA      *auth.MFA
	Recovery *auth.Recovery
	Now      func() time.Time
	Logger   *slog.Logger
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) challenges() challenges {
	return challenges{db: s.DB, ring: s.Ring, now: s.now}
}

var (
	errRegistration = fault.New(fault.InvalidRequest, "Passkey registration failed")
	errLimit        = fault.New(fault.Conflict, "Passkey limit reached")
	errDuplicate    = fault.New(fault.Conflict, "Passkey is already registered")
	// ErrAssertion is every refusal of a passkey assertion; the reason is
	// only logged.
	ErrAssertion = fault.New(fault.AuthenticationNeeded, "Passkey authentication failed")
)

// NormalizeName is the passkey name rule of the Python release: trimmed,
// at most 80 characters, "Passkey" when empty.
func NormalizeName(name string) string {
	name = strings.TrimFunc(name, unicode.IsSpace)
	if r := []rune(name); len(r) > MaxNameChars {
		name = string(r[:MaxNameChars])
	}
	if name == "" {
		return DefaultName
	}
	return name
}

func registrationBinding(p principal.Principal, ceremony string) (string, error) {
	if len(ceremony) < minCeremonyChars || len(ceremony) > maxCeremonyChars {
		return "", errRegistration
	}
	sum := sha256.Sum256([]byte(ceremony))
	return "register:" + p.SessionID + ":" + hex.EncodeToString(sum[:]), nil
}

// BeginRegistration returns the creation options of a new passkey of the
// principal's account, with a ceremony token that ties the answer to this
// browser session. A legacy upgrade does not exclude the existing
// credentials, so an authenticator can replace a non-discoverable one. The
// caller has consumed the passkey.enroll grant (or the session is a
// recovery session).
func (s *Service) BeginRegistration(ctx context.Context, p principal.Principal, legacyUpgrade bool) (jsontext.Value, error) {
	existing, err := s.credentialIDs(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	if len(existing) >= MaxPasskeys {
		return nil, errLimit
	}
	if legacyUpgrade {
		existing = nil
	}
	var raw [24]byte
	_, _ = rand.Read(raw[:]) // crypto/rand.Read never fails
	ceremony := base64.RawURLEncoding.EncodeToString(raw[:])
	binding, err := registrationBinding(p, ceremony)
	if err != nil {
		return nil, err
	}
	challenge, err := s.challenges().issue(ctx, purposeRegister, p.UserID, binding)
	if err != nil {
		return nil, err
	}
	return s.RP.creationJSON(p.UserID, p.Username, challenge, existing, ceremony)
}

// FinishRegistration verifies the authenticator's answer to a ceremony of
// the principal's session and stores the passkey. In a recovery session
// it ends the restriction in the same transaction. Every verification
// failure is errRegistration; its reason is returned wrapped for the
// audit log.
func (s *Service) FinishRegistration(ctx context.Context, p principal.Principal, ceremony string, credential jsontext.Value, name string) (int64, error) {
	binding, err := registrationBinding(p, ceremony)
	if err != nil {
		return 0, err
	}
	challenge, err := s.challenges().consume(ctx, purposeRegister, p.UserID, binding)
	if err != nil {
		return 0, fault.Wrap(fault.InvalidRequest, err, "Passkey registration failed")
	}
	reg, err := s.RP.VerifyRegistration(credential, challenge)
	if err != nil {
		return 0, fault.Wrap(fault.InvalidRequest, err, "Passkey registration failed")
	}
	transports, err := json.Marshal(reg.Transports)
	if err != nil {
		return 0, fmt.Errorf("webauthn: transports: %w", err)
	}
	var id int64
	err = s.DB.Write(ctx, func(tx *store.Tx) error {
		n, err := s.Count(ctx, tx, p.UserID)
		if err != nil {
			return err
		}
		if n >= MaxPasskeys {
			return errLimit
		}
		var dup int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM webauthn_credentials WHERE credential_id = ?`, reg.CredentialID).Scan(&dup); err != nil {
			return fmt.Errorf("webauthn: check passkey: %w", err)
		}
		if dup != 0 {
			return errDuplicate
		}
		if err := tx.QueryRowContext(ctx, `INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count, transports,
			name, backup_eligible, backup_state, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`,
			p.UserID, reg.CredentialID, reg.COSEKey, int64(reg.SignCount), string(transports), NormalizeName(name),
			reg.Flags&FlagBE != 0, reg.Flags&FlagBS != 0, s.now().UnixMicro()).Scan(&id); err != nil {
			return fault.Wrap(fault.Unavailable, fmt.Errorf("webauthn: store passkey: %w", err), "Passkey storage is temporarily unavailable")
		}
		if p.Recovery {
			return s.MFA.Sessions.EndRecovery(ctx, tx, p.SessionID, "passkey", false)
		}
		return nil
	})
	return id, err
}

// AssertionOptions starts a step-up assertion (stepup.Passkeys): the
// account's passkeys are allowed, the challenge is bound to binding.
func (s *Service) AssertionOptions(ctx context.Context, userID int64, binding string) (jsontext.Value, error) {
	return s.options(ctx, purposeStepUp, userID, binding)
}

// VerifyAssertion checks a step-up assertion (stepup.Passkeys).
func (s *Service) VerifyAssertion(ctx context.Context, userID int64, binding string, credential jsontext.Value) error {
	_, _, err := s.assert(ctx, purposeStepUp, userID, binding, credential)
	return err
}

var errNoPasskey = fault.New(fault.Conflict, "No passkey is available")

// SignInOptions starts a passkey sign-in bound to the browser binding.
// With pendingUser 0 it is a sign-in without a user name; otherwise the
// passkey completes the pending sign-in of that account and only its
// credentials are allowed.
func (s *Service) SignInOptions(ctx context.Context, binding string, pendingUser int64) (jsontext.Value, error) {
	if pendingUser == 0 {
		return s.options(ctx, purposeLogin, 0, binding)
	}
	return s.options(ctx, purposeMFA, pendingUser, binding)
}

// SignIn verifies a sign-in assertion started by SignInOptions with the
// same pendingUser and returns the account it proves.
func (s *Service) SignIn(ctx context.Context, binding string, pendingUser int64, credential jsontext.Value) (int64, error) {
	userID, _, err := s.SignInPasskey(ctx, binding, pendingUser, credential)
	return userID, err
}

// SignInPasskey is SignIn that also returns the row id of the passkey
// that signed, for the caller to confirm it still exists (Owned) when the
// session is issued.
func (s *Service) SignInPasskey(ctx context.Context, binding string, pendingUser int64, credential jsontext.Value) (userID, passkeyID int64, err error) {
	if pendingUser == 0 {
		return s.assert(ctx, purposeLogin, 0, binding, credential)
	}
	return s.assert(ctx, purposeMFA, pendingUser, binding, credential)
}

func (s *Service) options(ctx context.Context, purpose string, userID int64, binding string) (jsontext.Value, error) {
	var allow [][]byte
	if userID != 0 {
		ids, err := s.credentialIDs(ctx, userID)
		if err != nil {
			return nil, err
		}
		if len(ids) == 0 {
			return nil, errNoPasskey
		}
		allow = ids
	}
	challenge, err := s.challenges().issue(ctx, purpose, userID, binding)
	if err != nil {
		return nil, err
	}
	return s.RP.requestJSON(challenge, allow)
}

// assert consumes the challenge of purpose, verifies the assertion against
// the stored credential and records its use. userID 0 accepts any
// account's passkey, identified by its user handle. Refusals are
// ErrAssertion wrapping the reason; storage failures pass through.
func (s *Service) assert(ctx context.Context, purpose string, userID int64, binding string, credential jsontext.Value) (int64, int64, error) {
	challenge, err := s.challenges().consume(ctx, purpose, userID, binding)
	if err != nil {
		return 0, 0, refused(err)
	}
	a, err := ParseAssertion(credential)
	if err != nil {
		return 0, 0, refused(err)
	}
	r, err := s.lookup(ctx, a.CredentialID, userID)
	if err != nil {
		return 0, 0, refused(err)
	}
	v, err := s.RP.Verify(a, r.stored, Expect{Challenge: challenge, HandleRequired: purpose == purposeLogin})
	if err != nil {
		return 0, 0, refused(err)
	}
	err = s.DB.Write(ctx, func(tx *store.Tx) error {
		if err := s.recordUse(ctx, tx, r, v); err != nil {
			return err
		}
		return auth.ClearTx(ctx, tx, r.userID)
	})
	if err != nil {
		return 0, 0, refused(err)
	}
	return r.userID, r.id, nil
}

// refused maps a failed assertion to ErrAssertion, keeping the cause for
// the log. Storage failures are not the client's fault and stay what they
// are.
func refused(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if fe, ok := fault.From(err); ok && fe.Code != fault.NotFound && fe.Code != fault.Conflict {
		return err
	}
	return fault.Wrap(fault.AuthenticationNeeded, err, "Passkey authentication failed")
}

var (
	errRecoveryOff  = fault.New(fault.Conflict, "Recovery codes must be active before enabling MFA")
	errMFAOn        = fault.New(fault.Conflict, "MFA is already enabled")
	errNeedsPasskey = fault.New(fault.Conflict, "Add a Passkey before enabling MFA")
)

// EnableMFA requires a second factor after every password or directory
// sign-in of the principal's account, which must have a passkey. It
// replaces the recovery codes and returns the new ones. The caller has
// consumed the mfa.enable grant.
func (s *Service) EnableMFA(ctx context.Context, p principal.Principal) ([]string, error) {
	on := false
	if s.MFA.Gates != nil {
		var err error
		if on, err = s.MFA.Gates.Active(ctx, auth.FeatureRecovery); err != nil {
			return nil, err
		}
	}
	if !on {
		return nil, errRecoveryOff
	}
	var codes []string
	err := s.DB.Write(ctx, func(tx *store.Tx) error {
		on, err := s.MFA.Accounts.MFARequired(ctx, tx, p.UserID)
		if err != nil {
			return err
		}
		if on {
			return errMFAOn
		}
		n, err := s.Count(ctx, tx, p.UserID)
		if err != nil {
			return err
		}
		if n == 0 {
			return errNeedsPasskey
		}
		if codes, err = s.Recovery.ReplaceTx(ctx, tx, p.UserID, auth.RecoveryCodeCount); err != nil {
			return err
		}
		return s.MFA.Accounts.SetMFARequired(ctx, tx, p.UserID, true)
	})
	return codes, err
}

// Factor is the passkey entry of the auth factor registry. A passkey
// answers a challenge bound to the browser, so it is verified through the
// sign-in routes of this package, never through Verify.
type Factor struct{ Service *Service }

// Kind implements auth.Factor.
func (Factor) Kind() string { return "passkey" }

// Enrolled implements auth.Factor.
func (f Factor) Enrolled(ctx context.Context, userID int64) (bool, error) {
	return f.Service.Enrolled(ctx, userID)
}

// Verify implements auth.Factor; it always refuses.
func (Factor) Verify(context.Context, int64, jsontext.Value) error {
	return fault.New(fault.AuthFailed, "Passkeys are verified by their own sign-in routes")
}

// Reason names why a ceremony was refused, for the audit log; like the
// Python release it records the kind of failure, never input or error
// text.
func Reason(err error) string {
	for _, r := range []struct {
		err  error
		name string
	}{
		{errChallenge, "challenge"}, {errClientData, "client_data"}, {errRPID, "rp_id"}, {errUser, "user_verification"},
		{errCounter, "counter"}, {errBackup, "backup_flags"}, {errHandle, "user_handle"}, {errSignature, "signature"},
		{errAttestation, "attestation"}, {errCOSE, "public_key"}, {errAuthData, "authenticator_data"}, {errCBOR, "cbor"},
		{errCredential, "credential"}, {errNotFound, "unknown_credential"},
	} {
		if errors.Is(err, r.err) {
			return r.name
		}
	}
	if _, code, _ := fault.Status(err); code != fault.Internal {
		return string(code)
	}
	return "other"
}
