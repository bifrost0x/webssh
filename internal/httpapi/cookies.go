package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

// cookieJar writes one cookie with the attributes of the session cookie:
// HttpOnly, SameSite=Lax, Secure as SESSION_COOKIE_SECURE says, and the
// path of APPLICATION_ROOT.
type cookieJar struct {
	name   string
	path   string
	secure bool
}

func (c cookieJar) set(w http.ResponseWriter, value string, expires time.Time) {
	// #nosec G124 -- HttpOnly and SameSite are fixed; Secure follows SESSION_COOKIE_SECURE, which the homelab profile may turn off for plain HTTP
	http.SetCookie(w, &http.Cookie{
		Name: c.name, Value: value, Path: c.path, Expires: expires,
		HttpOnly: true, Secure: c.secure, SameSite: http.SameSiteLaxMode,
	})
}

func (c cookieJar) clear(w http.ResponseWriter) {
	// #nosec G124 -- same attributes as set
	http.SetCookie(w, &http.Cookie{
		Name: c.name, Value: "", Path: c.path, MaxAge: -1,
		HttpOnly: true, Secure: c.secure, SameSite: http.SameSiteLaxMode,
	})
}

// SessionCookie writes and clears the session cookie for the sign-in flow;
// the composition root hands it to the capability that issues sessions.
type SessionCookie struct{ jar cookieJar }

// Name returns the cookie name (SESSION_COOKIE_NAME).
func (c SessionCookie) Name() string { return c.jar.name }

// Set stores a session token. A zero expiry makes a browser-session
// cookie.
func (c SessionCookie) Set(w http.ResponseWriter, token string, expires time.Time) {
	c.jar.set(w, token, expires)
}

// Clear removes the session cookie.
func (c SessionCookie) Clear(w http.ResponseWriter) { c.jar.clear(w) }

// cookiePath is APPLICATION_ROOT when it is an absolute path, else "/".
func cookiePath(root string) string {
	if strings.HasPrefix(root, "/") && root != "" {
		return root
	}
	return "/"
}

// bindingName derives the binding cookie name from the session cookie
// name; it must not collide with the remember cookie.
func bindingName(session, remember string) (string, error) {
	name := session + bindingSuffix
	if name == remember {
		return "", errors.New("httpapi: REMEMBER_COOKIE_NAME collides with the CSRF binding cookie " + name)
	}
	return name, nil
}
