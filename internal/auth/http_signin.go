package auth

import (
	"net/http"
	"time"
)

// PendingLogin is a sign-in that passed the primary factor and waits for
// the second one.
type PendingLogin struct {
	UserID int64
	// PrimaryMethod is "password" or "ldap"; recovery codes complete only
	// those.
	PrimaryMethod string
}

// PendingSignIn is the pending sign-in of the login flow, bound to the
// browser (provided by the sign-in flow of this package).
type PendingSignIn interface {
	// Pending returns the request's pending sign-in or fails with
	// fault.AuthenticationNeeded.
	Pending(r *http.Request) (PendingLogin, error)
	// Complete turns the pending sign-in into a browser session with factor
	// added to its methods and returns the continuation path.
	Complete(w http.ResponseWriter, r *http.Request, userID int64, factor string, assurance Assurance) (continuation string, err error)
	// Discard drops the pending sign-in and queues the "Sign in again"
	// notice with the name hint for the password form.
	Discard(w http.ResponseWriter, r *http.Request) error
}

// RuleLimiter is the part of the sign-in flow's rate limiter (*Limiter)
// the factor routes use. Allow reports whether one more hit on key fits
// into r.
type RuleLimiter interface {
	Allow(key string, r Rule) (bool, time.Duration)
}

// FactorLimits applies RATELIMIT_* to the factor routes as the Python
// release does: per source address, and for reauthentication per user and
// source. It shares the Limiter of the sign-in forms (Flow.Limiter).
type FactorLimits struct {
	Limiter RuleLimiter
	// Enabled is RATELIMIT_ENABLED.
	Enabled bool
	// Login is RATELIMIT_LOGIN_LIMIT, Reauth is RATELIMIT_REAUTH.
	Login, Reauth Rule
	// ClientAddr returns the normalised client address of r (from the HTTP
	// edge, after TRUSTED_PROXIES).
	ClientAddr func(r *http.Request) string
}

func (l FactorLimits) addr(r *http.Request) string {
	if l.ClientAddr == nil {
		return "unknown"
	}
	if a := l.ClientAddr(r); a != "" {
		return a
	}
	return "unknown"
}

// SourceLimited reports whether endpoint is over the login limit for the
// request's source.
func (l FactorLimits) SourceLimited(r *http.Request, endpoint string) bool {
	return l.Enabled && l.Limiter != nil && !l.allow(endpoint+":"+l.addr(r), l.Login)
}

// UserLimited reports whether endpoint is over limit for the user or the
// source. Both buckets are charged, like check_reauth_rate_limit.
func (l FactorLimits) UserLimited(r *http.Request, userID int64, endpoint string, limit Rule) bool {
	if !l.Enabled || l.Limiter == nil {
		return false
	}
	user := l.allow(endpoint+":user:"+itoa(userID), limit)
	source := l.allow(endpoint+":ip:"+l.addr(r), limit)
	return !(user && source)
}

// ReauthLimited is UserLimited with RATELIMIT_REAUTH.
func (l FactorLimits) ReauthLimited(r *http.Request, userID int64, endpoint string) bool {
	return l.UserLimited(r, userID, endpoint, l.Reauth)
}

func (l FactorLimits) allow(key string, r Rule) bool {
	ok, _ := l.Limiter.Allow(key, r)
	return ok
}
