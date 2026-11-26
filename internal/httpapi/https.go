package httpapi

import "net/http"

// ReachedOverHTTPS reports whether the browser talked to WebSSH over
// HTTPS (request_reached_over_https of the Python release): direct TLS or
// a trusted proxy that says so, or a same-host page the browser loaded
// over https:// as Origin or Referer state. Saved passwords need it.
func ReachedOverHTTPS(r *http.Request) bool {
	return infoFrom(r).Scheme == "https" || reachedOverHTTPS(r)
}
