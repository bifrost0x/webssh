package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/config"
	"github.com/bifrost0x/webssh/internal/principal"
)

// SessionValidator resolves a session cookie; internal/session provides
// it. Authenticate fails with authentication_required for every token that
// does not name a valid, unexpired session.
type SessionValidator interface {
	Authenticate(ctx context.Context, token string) (principal.Principal, error)
}

// Options are the dependencies of the HTTP edge.
type Options struct {
	Config   config.Config
	Sessions SessionValidator
	// MAC derives the CSRF tokens (keyring purpose CSRF).
	MAC    MACer
	Assets *Assets
	// Renderer renders the error page; without it failures of page
	// requests are plain text.
	Renderer *Renderer
	// ErrorPageData returns the base data of the error page (theme, user)
	// for a request; optional.
	ErrorPageData func(r *http.Request) PageData
	Readiness     Readiness
	Logger        *slog.Logger
}

// Handler is the HTTP edge: it resolves the client address, applies the
// security headers, request limits, the session, the access level of the
// route and the CSRF and origin checks, and then dispatches to the
// handlers the capabilities registered on Mux.
type Handler struct {
	cfg      config.Config
	sessions SessionValidator
	mac      MACer
	renderer *Renderer
	pageData errorPageData
	log      *slog.Logger
	proxy    *proxyTrust
	cop      *http.CrossOriginProtection
	session  cookieJar
	binding  cookieJar

	mux    *http.ServeMux
	access map[string]Access
	// streamed are the routes whose body the handler reads itself
	// (StreamBody).
	streamed map[string]bool
	ready    *readiness

	finish    sync.Once
	finishErr error
	filled    []string // catalog routes Finish found without a handler
}

// New builds the edge with the probes, static files, the realtime status
// route and the preview catalog registered. Capabilities add their routes
// on Mux before the first request.
func New(o Options) (*Handler, error) {
	if o.Sessions == nil || o.MAC == nil || o.Assets == nil {
		return nil, errors.New("httpapi: Sessions, MAC and Assets are required")
	}
	log := o.Logger
	if log == nil {
		log = slog.Default()
	}
	cfg := o.Config
	bindingCookie, err := bindingName(cfg.Cookies.SessionName, cfg.Cookies.RememberName)
	if err != nil {
		return nil, err
	}
	path := cookiePath(cfg.ApplicationRoot)
	h := &Handler{
		cfg: cfg, sessions: o.Sessions, mac: o.MAC, renderer: o.Renderer,
		pageData: o.ErrorPageData, log: log,
		proxy:   newProxyTrust(cfg.Proxies.Hops, cfg.Proxies.CIDRs, log),
		cop:     http.NewCrossOriginProtection(),
		session: cookieJar{name: cfg.Cookies.SessionName, path: path, secure: cfg.Cookies.Secure},
		binding: cookieJar{name: bindingCookie, path: path, secure: cfg.Cookies.Secure},
		mux:     http.NewServeMux(),
		access:  map[string]Access{},
	}
	if h.session.name == "" {
		return nil, errors.New("httpapi: the session cookie name is empty")
	}
	for _, rt := range catalogRoutes() {
		h.access[patternKey(rt.pattern)] = rt.access
	}
	for p := range droppedRoutes {
		h.access[patternKey(p)] = AccessGone
		h.mux.Handle(p, http.HandlerFunc(h.unwired))
	}
	h.mux.Handle("/socket.io/", http.HandlerFunc(gone))
	h.mux.Handle("/socket.io", http.HandlerFunc(gone))
	h.access[patternKey("/socket.io/")] = AccessGone
	h.access[patternKey("/socket.io")] = AccessGone

	h.ready = newReadiness(o.Readiness, log)
	h.mux.HandleFunc("GET "+pathHealth, health)
	h.mux.Handle("GET "+pathReady, h.ready)
	h.mux.Handle("GET "+pathStatic+"{path...}", newStatic(o.Assets))
	h.mux.HandleFunc("GET "+pathRealtimeState, h.realtimeStatus)
	return h, nil
}

// Mux is where capabilities register their routes, with patterns
// relative to the application root. Every pattern must be in the route
// catalog; a route the catalog does not know is refused.
func (h *Handler) Mux() *http.ServeMux { return h.mux }

// SessionCookie returns the writer of the session cookie for the sign-in
// flow.
func (h *Handler) SessionCookie() SessionCookie { return SessionCookie{jar: h.session} }

// Finish completes the routing: every catalog route without a handler
// answers 404 like a route that does not exist, so a capability that is
// not wired leaves nothing open. It returns the patterns it filled; the
// composition root refuses to start when there are any. ServeHTTP calls
// it before the first request. Registering routes afterwards is a
// programming error.
func (h *Handler) Finish() (filled []string, err error) {
	h.finish.Do(func() {
		defer func() {
			if v := recover(); v != nil {
				h.finishErr = fmt.Errorf("httpapi: complete the route catalog: %v", v)
			}
		}()
		for _, rt := range catalogRoutes() {
			if h.registered(rt.pattern) {
				continue
			}
			h.mux.Handle(rt.pattern, http.HandlerFunc(h.unwired))
			h.filled = append(h.filled, rt.pattern)
		}
	})
	return slices.Clone(h.filled), h.finishErr
}

// registered reports whether the mux already has a handler for exactly
// this catalog pattern.
func (h *Handler) registered(pattern string) bool {
	method, path := samplePath(pattern)
	req, err := http.NewRequest(method, "http://localhost"+path, nil)
	if err != nil {
		return false
	}
	_, got := h.mux.Handler(req)
	return got != "" && patternKey(got) == patternKey(pattern)
}

// ServeHTTP runs the pipeline in this order: client address, headers,
// admin panel gate, edge-answered routes, deadlines, body limit, session,
// access level, origin and CSRF, handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if _, err := h.Finish(); err != nil {
		h.log.Error("routing is incomplete", "err", err)
		writePlain(w, http.StatusInternalServerError, "An internal error occurred.")
		return
	}
	info := h.proxy.resolve(r)
	r = r.WithContext(withInfo(r.Context(), info))
	setSecurityHeaders(w.Header(), h.cfg.Debug)
	rec := &statusRecorder{ResponseWriter: w}
	started := time.Now()
	defer h.logRequest(rec, r, started)
	defer h.recoverPanic(rec, r)
	h.serve(rec, r)
}

func (h *Handler) serve(w http.ResponseWriter, r *http.Request) {
	_, pattern := h.mux.Handler(r)
	if pattern == "" {
		// Not found, wrong method or a redirect to the clean path.
		h.mux.ServeHTTP(w, r)
		return
	}
	access := h.access[patternKey(pattern)]
	if adminGated(r.URL.Path) && !h.cfg.Accounts.AdminPanelEnabled {
		h.fail(w, r, errNotFound, "", "")
		return
	}
	switch access {
	case AccessGone, AccessUpgrade:
		h.mux.ServeHTTP(w, r)
		return
	case AccessProbe:
		setDeadlines(w, h.log)
		h.mux.ServeHTTP(w, r)
		return
	case 0:
		h.log.Error("route is not in the catalog; refused", "pattern", pattern)
		h.fail(w, r, errNotFound, "", "")
		return
	}
	setDeadlines(w, h.log)
	var body []byte
	if unsafeMethod(r.Method) && !h.streamed[patternKey(pattern)] {
		b, ok, err := readBody(w, r, h.bodyLimit(r.URL.Path))
		if err != nil {
			// The client stopped sending or the read deadline passed.
			writePlain(w, http.StatusBadRequest, "The request body could not be read.")
			return
		}
		if !ok {
			h.tooLarge(w, r)
			return
		}
		body = b
	}
	r, ok := h.authenticate(w, r, access)
	if p, signedIn := principal.From(r.Context()); signedIn {
		if rec, isRec := w.(*statusRecorder); isRec {
			rec.userID = p.UserID
		}
	}
	if !ok {
		return
	}
	if unsafeMethod(r.Method) {
		if err := h.originCheck(r); err != nil {
			h.fail(w, r, err, kindForbidden, "")
			return
		}
		if err := h.csrfCheck(r, body); err != nil {
			h.csrfFailed(w, r, pattern)
			return
		}
	}
	h.mux.ServeHTTP(w, r)
}

func unsafeMethod(m string) bool {
	return m != http.MethodGet && m != http.MethodHead && m != http.MethodOptions
}
