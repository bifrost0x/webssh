package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/url"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

// FlightTTL is how long a redirect may take from Begin to the callback
// (the five minutes of the Python login state).
const FlightTTL = 5 * time.Minute

// Random lengths of a flight, as secrets.token_urlsafe(32) and (64) in
// the Python release: 43 and 86 characters of base64url.
const (
	stateBytes    = 32
	verifierBytes = 64
	// maxCallbackField bounds every callback parameter; longer values are
	// refused before any comparison.
	maxCallbackField = 4096
)

// Flight is one redirect in progress. The flow stores it server-side,
// bound to the browser binding, and consumes it exactly once: a second
// callback with the same state finds nothing.
type Flight struct {
	Provider ProviderName
	Purpose  Purpose
	State    string
	Nonce    string // OIDC only; GitHub has none
	Verifier string // PKCE (RFC 7636, S256)
	// UserID, Generation and SessionID bind link and step-up flights to
	// the account, its auth generation and the browser session that
	// started them; a change of any of them rejects the callback.
	UserID     int64
	Generation int64
	SessionID  string
	// Intent is the step-up intent token of a step-up flight
	// (internal/auth/stepup); Action and Target are the administrator
	// action and its target, empty for an account step-up.
	Intent string
	Action principal.Action
	Target string
	// Continuation is the local path to return to after sign-in.
	Continuation string
	IssuedAt     time.Time
}

// NewFlight starts a flight with fresh state, nonce and verifier.
func NewFlight(provider ProviderName, purpose Purpose, now time.Time) Flight {
	return Flight{
		Provider: provider, Purpose: purpose,
		State: token(stateBytes), Nonce: token(stateBytes), Verifier: token(verifierBytes),
		IssuedAt: now,
	}
}

func token(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b) // crypto/rand.Read never fails (Go 1.24)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Challenge is the PKCE S256 code challenge of the verifier.
func (f Flight) Challenge() string {
	sum := sha256.Sum256([]byte(f.Verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Accept checks the callback against the flight: same state (constant
// time), not expired, no error from the provider, a code present. Every
// refusal is fault.AuthFailed; the provider's error text is never shown.
func (f Flight) Accept(cb Callback, now time.Time) error {
	if f.State == "" || subtle.ConstantTimeCompare([]byte(f.State), []byte(cb.State)) != 1 {
		return fault.New(fault.AuthFailed, "")
	}
	if f.IssuedAt.IsZero() || now.Before(f.IssuedAt) || now.Sub(f.IssuedAt) > FlightTTL {
		return fault.New(fault.AuthFailed, "")
	}
	if cb.Error != "" || cb.Code == "" {
		return fault.New(fault.AuthFailed, "")
	}
	return nil
}

// Callback is the query of a provider's redirect back to WebSSH.
type Callback struct {
	Code  string
	State string
	// Error is the provider's error parameter (for example access_denied);
	// it is logged as a code, never shown.
	Error string
}

// ParseCallback reads the callback query. A repeated or oversized
// parameter is fault.AuthFailed, so a crafted query cannot pick which of
// two states is compared.
func ParseCallback(q url.Values) (Callback, error) {
	var cb Callback
	for name, dst := range map[string]*string{"code": &cb.Code, "state": &cb.State, "error": &cb.Error} {
		v := q[name]
		switch {
		case len(v) == 0:
		case len(v) > 1 || len(v[0]) > maxCallbackField:
			return Callback{}, fault.New(fault.AuthFailed, "")
		default:
			*dst = v[0]
		}
	}
	return cb, nil
}
