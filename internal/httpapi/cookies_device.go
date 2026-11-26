package httpapi

import (
	"net/http"
	"time"
)

// deviceSuffix names the known-device cookie after the session cookie, as
// the Python release does (login_devices.cookie_name).
const deviceSuffix = "_device"

// DeviceCookie writes the known-device cookie of the password sign-in
// (<SESSION_COOKIE_NAME>_device) with the attributes of the session
// cookie.
type DeviceCookie struct{ jar cookieJar }

// DeviceCookie returns the writer of the known-device cookie.
func (h *Handler) DeviceCookie() DeviceCookie {
	return DeviceCookie{jar: cookieJar{name: h.session.name + deviceSuffix, path: h.session.path, secure: h.session.secure}}
}

// Name returns the cookie name.
func (c DeviceCookie) Name() string { return c.jar.name }

// Set stores value until expires.
func (c DeviceCookie) Set(w http.ResponseWriter, value string, expires time.Time) {
	c.jar.set(w, value, expires)
}
