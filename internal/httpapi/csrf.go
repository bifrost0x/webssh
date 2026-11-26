package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/keyring"
)

// MACer computes the keyring MAC of a purpose; *keyring.Ring provides it.
type MACer interface {
	MAC(p keyring.Purpose, msg []byte) []byte
}

// CSRF protection.
//
// Every browser gets a binding cookie: a random value, HttpOnly, that the
// page cannot read. The CSRF token is the keyring MAC (purpose CSRF) of
// that value and of the session ID when a session is signed in, so a token
// is valid only in the browser it was issued to and only for its session;
// signing in or out changes it. Unsafe requests carry the token in
// X-CSRFToken (or X-CSRF-Token), or in the form field csrf_token, as the
// Python release accepted them. Tokens do not expire on their own
// (WTF_CSRF_TIME_LIMIT=None).
//
// A handler that issues or ends a session therefore answers with a
// redirect or JSON, never with a form rendered in the same response.
const (
	csrfTokenVersion = "webssh-csrf-v1\x00" // #nosec G101 -- domain separation prefix of the MAC input, not a secret
	bindingBytes     = 32
	csrfFormField    = "csrf_token"
	bindingSuffix    = "_binding"
	maxTokenLen      = 256
)

var errCSRF = fault.New(fault.CSRFExpired, "This page expired. Reload it and try again.")

type csrfState struct {
	binding string
	token   string
	// fresh is true when the request carried no valid binding cookie.
	fresh bool
}

type csrfKey struct{}

// CSRFToken returns the token for the page of this request, the value of
// the csrf-token meta tag and of hidden form fields. It is "" for
// requests that do not pass the session layer (probes, static files,
// the realtime endpoint).
func CSRFToken(r *http.Request) string {
	if s, ok := r.Context().Value(csrfKey{}).(*csrfState); ok {
		return s.token
	}
	return ""
}

// BrowserBinding returns the random value that identifies this browser
// across sign-in, for flows that bind a pending sign-in to the browser.
// It is never sent to the page.
func BrowserBinding(r *http.Request) string {
	if s, ok := r.Context().Value(csrfKey{}).(*csrfState); ok {
		return s.binding
	}
	return ""
}

func validBinding(v string) bool {
	if len(v) != base64.RawURLEncoding.EncodedLen(bindingBytes) {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(v)
	return err == nil && len(b) == bindingBytes
}

func newBinding() string {
	b := make([]byte, bindingBytes)
	_, _ = rand.Read(b) // crypto/rand.Read never fails
	return base64.RawURLEncoding.EncodeToString(b)
}

func (h *Handler) csrfToken(binding, sessionID string) string {
	msg := csrfTokenVersion + binding + "\x00" + sessionID
	return base64.RawURLEncoding.EncodeToString(h.mac.MAC(keyring.CSRF, []byte(msg)))
}

// csrfBegin reads or creates the binding and computes the token for the
// request's session. A new binding is set as a cookie on the response.
func (h *Handler) csrfBegin(w http.ResponseWriter, r *http.Request, sessionID string) context.Context {
	s := &csrfState{}
	if c, err := r.Cookie(h.binding.name); err == nil && validBinding(c.Value) {
		s.binding = c.Value
	} else {
		s.binding, s.fresh = newBinding(), true
		h.binding.set(w, s.binding, time.Time{})
	}
	s.token = h.csrfToken(s.binding, sessionID)
	return context.WithValue(r.Context(), csrfKey{}, s)
}

// csrfCheck verifies the token of an unsafe request. body is the buffered
// request body.
func (h *Handler) csrfCheck(r *http.Request, body []byte) error {
	s, ok := r.Context().Value(csrfKey{}).(*csrfState)
	if !ok || s.fresh {
		return errCSRF
	}
	got := r.Header.Get("X-CSRFToken")
	if got == "" {
		got = r.Header.Get("X-CSRF-Token")
	}
	if got == "" {
		got = formToken(r, body)
	}
	if got == "" || len(got) > maxTokenLen {
		return errCSRF
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
		return errCSRF
	}
	return nil
}

// formToken reads csrf_token from an URL-encoded form body. The body is
// already bounded by the request limit.
func formToken(r *http.Request, body []byte) string {
	ct, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || ct != "application/x-www-form-urlencoded" {
		return ""
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return ""
	}
	if v := values[csrfFormField]; len(v) == 1 {
		return v[0]
	}
	return ""
}

var errCrossOrigin = fault.New(fault.Forbidden, "The request came from another site.")

// originCheck refuses unsafe requests that a browser sent from another
// origin. Sec-Fetch-Site and Origin decide through
// http.CrossOriginProtection, compared with the host the browser used
// (X-Forwarded-Host of a trusted proxy). A request with neither but with a
// Referer must name the same host, as Flask-WTF required for HTTPS. A
// request with none of the three is not a browser request; the CSRF token
// still applies.
func (h *Handler) originCheck(r *http.Request) error {
	info := infoFrom(r)
	probe := r.Clone(r.Context())
	probe.Host = info.Host
	if err := h.cop.Check(probe); err != nil {
		return errCrossOrigin
	}
	if r.Header.Get("Sec-Fetch-Site") != "" || r.Header.Get("Origin") != "" {
		return nil
	}
	ref := r.Header.Get("Referer")
	if ref == "" {
		return nil
	}
	u, err := url.Parse(ref)
	if err != nil || u.Host == "" || u.User != nil || !strings.EqualFold(u.Host, info.Host) {
		return errCrossOrigin
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errCrossOrigin
	}
	return nil
}
