package hostops

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/bifrost0x/webssh/internal/principal"
)

// apiError is an answer of the discovery and reachability routes in the
// form of the Python release: {"error": message, "code": code}.
type apiError struct {
	status        int
	code, message string
}

func (e *apiError) Error() string { return e.message }

var (
	errScanRunning   = &apiError{http.StatusConflict, "running", "A scan is already running. Wait for it or cancel it."}
	errScanBusy      = &apiError{http.StatusTooManyRequests, "busy", "Another discovery is running. Try again shortly."}
	errScanGone      = &apiError{http.StatusNotFound, "not_found", "Scan not found."}
	errScanRate      = &apiError{http.StatusTooManyRequests, "busy", "Too many scans. Try again later."}
	errUnavailable   = &apiError{http.StatusNotFound, "unavailable", "Host discovery is not available on this instance."}
	errNotPermitted  = &apiError{http.StatusForbidden, "forbidden", "Your account may not use this feature. Ask an administrator."}
	errNoWork        = &apiError{http.StatusServiceUnavailable, "unavailable", "WebSSH is not accepting new work."}
	errInvalidBody   = &apiError{http.StatusBadRequest, "invalid_request", "Invalid request."}
	errAuthRequired  = &apiError{http.StatusUnauthorized, "", "Authentication required"}
	errInternalCheck = &apiError{http.StatusInternalServerError, "internal", "The request could not be completed."}
)

// Limiter is the per-account rate limit of features without credentials
// (check_user_rate_limit): it records one event under key if fewer than
// limit lie in the window.
type Limiter interface {
	Allow(key string, limit int, window time.Duration) bool
}

// allowUser charges cost units, as check_user_rate_limit does: it stops
// at the first refusal, and units charged before it stay charged.
func allowUser(l Limiter, endpoint string, userID int64, limit int, window time.Duration, cost int) bool {
	key := endpoint + ":user:" + strconv.FormatInt(userID, 10)
	for range max(1, cost) {
		if !l.Allow(key, limit, window) {
			return false
		}
	}
	return true
}

// Permission reports whether p holds a permission of the derived settings
// (internal/settings: permission.hosts.discovery or
// permission.hosts.reachability).
type Permission func(ctx context.Context, p principal.Principal) (bool, error)

// KnownEndpoints returns the saved endpoints of an account (hosts, jump
// hosts, SOCKS5 proxies) in the form of knownKey.
type KnownEndpoints func(ctx context.Context, owner int64) (map[string]bool, error)

// DiscoveryHTTP serves /api/discovery/scans. Enabled is
// HOST_DISCOVERY_ENABLED, the ceiling of the permission; Accepting reports
// whether the server takes new work (not during maintenance or shutdown).
type DiscoveryHTTP struct {
	Scanner   *Scanner
	Enabled   bool
	Permitted Permission
	Known     KnownEndpoints
	Limiter   Limiter
	Accepting func() bool
	Logger    *slog.Logger
}

// Scan limits of the Python release: ten scans per account and hour.
const (
	scanRateLimit  = 10
	scanRateWindow = time.Hour
	maxScanBody    = 4 << 10
)

// Register adds the routes to mux, relative to APPLICATION_ROOT.
func (h *DiscoveryHTTP) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/discovery/scans", serveAPI(h.Logger, h.start))
	mux.HandleFunc("GET /api/discovery/scans/{scan_id}", serveAPI(h.Logger, h.view))
	mux.HandleFunc("DELETE /api/discovery/scans/{scan_id}", serveAPI(h.Logger, h.cancel))
}

// Available is host_discovery_available of the pages for p.
func (h *DiscoveryHTTP) Available(ctx context.Context, p principal.Principal) bool {
	if !h.Enabled || h.Permitted == nil {
		return false
	}
	ok, err := h.Permitted(ctx, p)
	return err == nil && ok
}

type scanRequest struct {
	Network jsontext.Value `json:"network"`
	Ports   jsontext.Value `json:"ports"`
}

// readObject decodes a JSON object body with only the members of out.
func readObject(r *http.Request, out any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxScanBody+1))
	if err != nil || len(body) > maxScanBody {
		return errInvalidBody
	}
	if v := jsontext.Value(bytes.TrimSpace(body)); v.Kind() != '{' || json.Unmarshal(v, out, json.RejectUnknownMembers(true)) != nil {
		return errInvalidBody
	}
	return nil
}

func (h *DiscoveryHTTP) start(r *http.Request, p principal.Principal) (int, any, error) {
	ctx := r.Context()
	if !h.Enabled {
		return 0, nil, errUnavailable
	}
	if h.Accepting != nil && !h.Accepting() {
		return 0, nil, errNoWork
	}
	if ok, err := h.Permitted(ctx, p); err != nil {
		return 0, nil, err
	} else if !ok {
		return 0, nil, errNotPermitted
	}
	var req scanRequest
	if err := readObject(r, &req); err != nil {
		return 0, nil, err
	}
	var network string
	if req.Network.Kind() != '"' || json.Unmarshal(req.Network, &network) != nil {
		return 0, nil, invalidNetwork(errScanNetwork)
	}
	prefix, addrs, err := parseNetwork(network)
	if err != nil {
		return 0, nil, invalidNetwork(err)
	}
	ports, err := parsePorts(req.Ports)
	if err != nil {
		return 0, nil, invalidNetwork(err)
	}
	known, err := h.Known(ctx, p.UserID)
	if err != nil {
		return 0, nil, err
	}
	if !allowUser(h.Limiter, "host_discovery", p.UserID, scanRateLimit, scanRateWindow, 1) {
		return 0, nil, errScanRate
	}
	view, err := h.Scanner.Start(ctx, p, prefix, addrs, ports, known)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusAccepted, view, nil
}

func invalidNetwork(err error) error {
	var e scanInputError
	if !errors.As(err, &e) {
		e = errScanNetwork
	}
	return &apiError{http.StatusBadRequest, "invalid_network", scanInputMessages[e]}
}

func (h *DiscoveryHTTP) view(r *http.Request, p principal.Principal) (int, any, error) {
	if err := h.stillPermitted(r.Context(), p); err != nil {
		return 0, nil, err
	}
	v, err := h.Scanner.View(p, r.PathValue("scan_id"))
	return http.StatusOK, v, err
}

func (h *DiscoveryHTTP) cancel(r *http.Request, p principal.Principal) (int, any, error) {
	if err := h.stillPermitted(r.Context(), p); err != nil {
		return 0, nil, err
	}
	v, err := h.Scanner.Cancel(p, r.PathValue("scan_id"))
	return http.StatusOK, v, err
}

// stillPermitted checks the permission again for a running or finished
// scan. Once it is withdrawn, the account's scans stop and their results
// are dropped, as on a session revocation; the answer is the one for a
// scan that does not exist.
func (h *DiscoveryHTTP) stillPermitted(ctx context.Context, p principal.Principal) error {
	if h.Permitted == nil {
		return errScanGone
	}
	ok, err := h.Permitted(ctx, p)
	if err != nil {
		return err
	}
	if !ok {
		h.Scanner.Revoked(principal.Revocation{UserID: p.UserID})
		return errScanGone
	}
	return nil
}

// serveAPI runs fn for the signed-in principal and writes its answer or
// error in the Python form, never cached.
func serveAPI(log *slog.Logger, fn func(*http.Request, principal.Principal) (int, any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := principal.Require(r.Context())
		if err != nil {
			writeAPI(w, errAuthRequired.status, map[string]string{"error": errAuthRequired.message})
			return
		}
		status, body, err := fn(r, p)
		if err == nil {
			writeAPI(w, status, body)
			return
		}
		var e *apiError
		if !errors.As(err, &e) {
			if log == nil {
				log = slog.Default()
			}
			log.ErrorContext(r.Context(), "host operations request failed", "path", r.URL.Path, "error", err)
			e = errInternalCheck
		}
		writeAPI(w, e.status, map[string]string{"error": e.message, "code": e.code})
	}
}

func writeAPI(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, body, json.Deterministic(true))
}
