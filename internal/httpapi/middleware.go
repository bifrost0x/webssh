package httpapi

import (
	"bufio"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"time"
)

// contentSecurityPolicy is the policy of the Python release with two
// fixes. connect-src is 'self' only: the realtime endpoint is same-origin,
// and 'self' covers ws: and wss: of the same host (CSP Level 3); the
// Python release also allowed WebSocket connections to every other host.
// img-src drops https:, because no page shows an image from another host;
// the Python release allowed images from every HTTPS origin.
const contentSecurityPolicy = "default-src 'self'; " +
	"script-src 'self'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; " +
	"font-src 'self' data:; " +
	"media-src 'self' data:; " +
	"connect-src 'self'; " +
	"base-uri 'self'; " +
	"object-src 'none'; " +
	"frame-ancestors 'none';"

// setSecurityHeaders adds the headers every response carries, as the
// Python release's add_security_headers does. Cache-Control defaults to
// no-store: pages and API answers carry account data; the static handler
// sets its own policy.
func setSecurityHeaders(h http.Header, debugMode bool) {
	h.Set("Content-Security-Policy", contentSecurityPolicy)
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-XSS-Protection", "0")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
	if !debugMode {
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}
	h.Set("Cache-Control", "no-store")
}

// Per-request deadlines. The listener has only a header timeout and an
// idle timeout, because a server-wide read or write timeout would stay on
// hijacked WebSocket connections; every other request gets these.
const (
	requestReadTimeout  = 30 * time.Second
	requestWriteTimeout = 2 * time.Minute
)

func setDeadlines(w http.ResponseWriter, log *slog.Logger) {
	rc := http.NewResponseController(w)
	now := time.Now()
	errR := rc.SetReadDeadline(now.Add(requestReadTimeout))
	errW := rc.SetWriteDeadline(now.Add(requestWriteTimeout))
	if err := errors.Join(errR, errW); err != nil && !errors.Is(err, http.ErrNotSupported) {
		log.Debug("request deadline not set", "err", err)
	}
}

// ConfigureServer sets the listener limits that belong to the edge: a
// header timeout, an idle timeout and a header size bound. It leaves
// ReadTimeout and WriteTimeout at zero; see setDeadlines.
func ConfigureServer(srv *http.Server) {
	srv.ReadHeaderTimeout = 10 * time.Second
	srv.IdleTimeout = 2 * time.Minute
	srv.ReadTimeout = 0
	srv.WriteTimeout = 0
	srv.MaxHeaderBytes = 64 << 10
}

// statusRecorder notes the status and size for the request log. It
// passes Hijack and the ResponseController methods through.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
	userID int64 // the signed-in user, for the log
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += int64(n)
	return n, err
}

// Unwrap lets http.ResponseController reach the connection.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// Hijack is needed by the WebSocket upgrade, which asserts the interface.
func (s *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	s.status = http.StatusSwitchingProtocols
	return http.NewResponseController(s.ResponseWriter).Hijack()
}

// Flush passes streaming writes through.
func (s *statusRecorder) Flush() {
	_ = http.NewResponseController(s.ResponseWriter).Flush()
}

// logRequest writes one line per request: method, path without query,
// status, size, duration, client address and user. Headers, cookies,
// queries and bodies never reach the log; queries may carry sign-in codes.
func (h *Handler) logRequest(w *statusRecorder, r *http.Request, started time.Time) {
	level := slog.LevelInfo
	if p := r.URL.Path; strings.HasPrefix(p, pathStatic) || p == pathHealth || p == pathReady {
		level = slog.LevelDebug
	}
	attrs := []slog.Attr{
		slog.String("method", r.Method),
		slog.String("path", truncate(LogPath(r.URL.Path), 256)),
		slog.Int("status", w.status),
		slog.Int64("bytes", w.bytes),
		slog.Int64("ms", time.Since(started).Milliseconds()),
		slog.String("client", ClientAddr(r).String()),
	}
	if w.userID != 0 {
		attrs = append(attrs, slog.Int64("user_id", w.userID))
	}
	h.log.LogAttrs(r.Context(), level, "request", attrs...)
}

// recoverPanic turns a panicking handler into a 500 with a log entry;
// http.ErrAbortHandler keeps its meaning.
func (h *Handler) recoverPanic(w *statusRecorder, r *http.Request) {
	v := recover()
	if v == nil {
		return
	}
	if v == http.ErrAbortHandler {
		panic(v)
	}
	h.log.ErrorContext(r.Context(), "handler panicked", "path", LogPath(r.URL.Path), "panic", fmt.Sprint(v), "stack", string(debug.Stack()))
	if w.status == 0 {
		writePlain(w, http.StatusInternalServerError, "An internal error occurred.")
	}
}

// tokenPaths are the path prefixes whose next segment is a bearer
// token: the one-time transfer tokens (TR1-1).
var tokenPaths = []string{"/api/transfers/"}

// LogPath is a request path as logs may show it: the token segment of a
// token route is replaced, below any APPLICATION_ROOT. A token is spent
// once it is used, but a refused or unused one would still be valid.
func LogPath(p string) string {
	for _, prefix := range tokenPaths {
		i := strings.Index(p, prefix)
		if i < 0 {
			continue
		}
		start := i + len(prefix)
		end := strings.IndexByte(p[start:], '/')
		if end < 0 {
			end = len(p) - start
		}
		if end > 0 {
			p = p[:start] + "[token]" + p[start+end:]
		}
	}
	return p
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
