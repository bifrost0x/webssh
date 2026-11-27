package automation

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/store"
)

// StepUpHeader carries the step-up grant of a request.
const StepUpHeader = "X-WebSSH-Step-Up"

// maxBody bounds a request body: a runbook of 20 steps of 8 KiB in JSON
// escapes fits.
const maxBody = 2 << 20

// HTTP serves the automation routes (automation_routes.py). The edge
// mounts it behind session, CSRF and origin checks.
type HTTP struct {
	Service *Service
	// HTTPS reports whether the browser reached WebSSH over HTTPS.
	HTTPS func(*http.Request) bool
	// InsecureLoopback is DEBUG with the homelab profile and
	// AUTOMATION_ALLOW_INSECURE_LOOPBACK: a direct loopback request
	// without proxy headers may use plain HTTP.
	InsecureLoopback bool
	// Proxied is TRUSTED_PROXIES configured; it turns the loopback
	// exception off.
	Proxied bool
	// Index is the URL of the workspace page for a request.
	Index  func(*http.Request) string
	Logger *slog.Logger
}

// Register adds the routes to mux, relative to APPLICATION_ROOT.
func (h *HTTP) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /automation", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, h.Index(r)+"#automation", http.StatusFound)
	})
	mux.HandleFunc("GET /api/automation/state", h.serve(h.state))
	mux.HandleFunc("POST /api/automation/runbooks", h.serve(h.saveRunbook))
	mux.HandleFunc("DELETE /api/automation/runbooks/{book_id}", h.serve(h.deleteRunbook))
	mux.HandleFunc("POST /api/automation/preview", h.serve(h.preview))
	mux.HandleFunc("POST /api/automation/start", h.serve(h.start))
	mux.HandleFunc("GET /api/automation/runs", h.serve(h.runs))
	mux.HandleFunc("POST /api/automation/runs/{run_id}/cancel", h.serve(h.cancel))
	mux.HandleFunc("DELETE /api/automation/runs/{run_id}", h.serve(h.deleteRun))
	mux.HandleFunc("POST /api/automation/runs/clear", h.serve(h.clearRuns))
	mux.HandleFunc("GET /api/automation/runs/{run_id}/export", h.export)
}

// reply is a JSON answer with its status.
type reply struct {
	status int
	body   jsontext.Value
}

func ok(members ...pyjson.Member) reply { return reply{http.StatusOK, pyjson.Object(members)} }

type handler func(ctx context.Context, p principal.Principal, r *http.Request, w http.ResponseWriter) (reply, error)

// secure is _secure: HTTPS, or the documented loopback exception for
// local development.
func (h *HTTP) secure(r *http.Request) error {
	if h.HTTPS != nil && h.HTTPS(r) {
		return nil
	}
	if h.InsecureLoopback && !h.Proxied && loopback(r.RemoteAddr) && !forwarded(r.Header) {
		return nil
	}
	return Fail("https_required")
}

// Secure reports whether r passes the HTTPS check of the automation
// routes, the loopback exception included; the schedule routes use it
// too.
func (h *HTTP) Secure(r *http.Request) bool { return h.secure(r) == nil }

func loopback(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.Unmap().IsLoopback()
}

func forwarded(hdr http.Header) bool {
	for name := range hdr {
		l := strings.ToLower(name)
		if l == "forwarded" || strings.HasPrefix(l, "x-forwarded-") {
			return true
		}
	}
	return false
}

// gate is _auth then _enabled.
func (h *HTTP) gate(r *http.Request) (principal.Principal, error) {
	p, err := principal.Require(r.Context())
	if err != nil {
		return principal.Principal{}, Fail("authentication_required")
	}
	on, err := h.Service.o.Switches.AutomationEnabled(r.Context())
	if err != nil || !on {
		return principal.Principal{}, Fail(string(fault.AutomationDisabled))
	}
	if err := h.secure(r); err != nil {
		return principal.Principal{}, err
	}
	if !h.Service.o.Accepting() {
		return principal.Principal{}, Fail("unavailable")
	}
	return p, nil
}

func (h *HTTP) serve(fn handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := h.gate(r)
		var out reply
		if err == nil {
			out, err = fn(r.Context(), p, r, w)
		}
		if err != nil {
			h.fail(w, r, err)
			return
		}
		write(w, out.status, out.body)
	}
}

func write(w http.ResponseWriter, status int, body jsontext.Value) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(append(body, '\n'))
}

func errorBody(message, code string, hosts []string) jsontext.Value {
	m := []pyjson.Member{{Name: "error", Value: pyjson.String(message)}, {Name: "code", Value: pyjson.String(code)}}
	if len(hosts) > 0 {
		items := make([]jsontext.Value, len(hosts))
		for i, n := range hosts {
			items[i] = pyjson.String(n)
		}
		m = append(m, pyjson.Member{Name: "hosts", Value: pyjson.Array(items)})
	}
	return pyjson.Object(m)
}

// fail answers with the code and the generic text of the Python release;
// the cause of a storage failure is logged, never sent.
func (h *HTTP) fail(w http.ResponseWriter, r *http.Request, err error) {
	var ae *Error
	var nd *NotDispatched
	switch {
	case errors.As(err, &ae) && ae.Code == "storage_unavailable":
		write(w, http.StatusConflict, errorBody("Automation storage could not be validated.", ae.Code, nil))
	case errors.As(err, &ae):
		write(w, HTTPStatus(ae.Code), errorBody("Automation request could not be completed.", ae.Code, ae.Hosts))
	case errors.As(err, &nd) && nd.Code == "storage_unavailable":
		write(w, http.StatusConflict, errorBody("Automation storage could not be validated.", nd.Code, nil))
	case errors.As(err, &nd):
		write(w, HTTPStatus(nd.Code), errorBody("Automation request could not be completed.", nd.Code, nil))
	default:
		if _, ok := errors.AsType[*storageError](err); !ok {
			err = &storageError{err}
		}
		h.logger().ErrorContext(r.Context(), "automation request failed", "path", r.URL.Path, "error", err)
		write(w, http.StatusServiceUnavailable, errorBody("Automation storage is unavailable.", "storage_unavailable", nil))
	}
}

func (h *HTTP) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

// body reads a JSON object as Flask's get_json(silent=True) did.
func body(w http.ResponseWriter, r *http.Request) (jsontext.Value, error) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		return nil, Fail("invalid_request")
	}
	v, rep, err := pyjson.Load(raw)
	if err != nil || v.Kind() != '{' || rep.LoneSurrogates {
		return nil, Fail("invalid_request")
	}
	return v, nil
}

func (h *HTTP) saveRunbook(ctx context.Context, p principal.Principal, r *http.Request, w http.ResponseWriter) (reply, error) {
	v, err := body(w, r)
	if err != nil {
		return reply{}, err
	}
	book, err := h.Service.SaveRunbook(ctx, p.UserID, v)
	if err != nil {
		return reply{}, err
	}
	return ok(pyjson.Member{Name: "runbook", Value: book.Value()}), nil
}

func (h *HTTP) deleteRunbook(ctx context.Context, p principal.Principal, r *http.Request, _ http.ResponseWriter) (reply, error) {
	if err := h.Service.DeleteRunbook(ctx, p.UserID, r.PathValue("book_id")); err != nil {
		return reply{}, err
	}
	return ok(pyjson.Member{Name: "deleted", Value: jsonBool(true)}), nil
}

func (h *HTTP) preview(ctx context.Context, p principal.Principal, r *http.Request, w http.ResponseWriter) (reply, error) {
	v, err := body(w, r)
	if err != nil {
		return reply{}, err
	}
	out, err := h.Service.Preview(ctx, p.UserID, p.SessionID, v)
	return reply{http.StatusOK, out}, err
}

// start checks the confirmation before it consumes the step-up grant, so
// a mistyped number does not cost a grant.
func (h *HTTP) start(ctx context.Context, p principal.Principal, r *http.Request, w http.ResponseWriter) (reply, error) {
	v, err := body(w, r)
	if err != nil {
		return reply{}, err
	}
	tokenV, _ := pyjson.Get(v, "intent")
	token, _ := pyString(tokenV)
	rv, err := h.Service.intents.get(token, p.UserID, p.SessionID, h.Service.o.Now(), false)
	if err != nil {
		return reply{}, err
	}
	confV, _ := pyjson.Get(v, "confirmation")
	confirmation, isStr := pyString(confV)
	if !isStr || confirmation != rv.confirmation() {
		return reply{}, Fail("confirmation_required")
	}
	if err := h.Service.o.StepUp.Consume(ctx, p, principal.ActionAutomationRun, token, r.Header.Get(StepUpHeader)); err != nil {
		return reply{}, Fail("step_up_required")
	}
	run, err := h.Service.Start(ctx, p.UserID, p.SessionID, token, confirmation)
	if err != nil {
		return reply{}, err
	}
	return reply{http.StatusAccepted, pyjson.Object([]pyjson.Member{{Name: "run", Value: run.Value()}})}, nil
}

func (h *HTTP) runs(ctx context.Context, p principal.Principal, _ *http.Request, _ http.ResponseWriter) (reply, error) {
	runs, err := h.Service.History(ctx, p.UserID)
	if err != nil {
		return reply{}, err
	}
	items := make([]jsontext.Value, len(runs))
	for i := range runs {
		items[i] = runs[i].Value()
	}
	return ok(pyjson.Member{Name: "runs", Value: pyjson.Array(items)}), nil
}

func (h *HTTP) cancel(ctx context.Context, p principal.Principal, r *http.Request, _ http.ResponseWriter) (reply, error) {
	if err := h.Service.Cancel(ctx, p.UserID, r.PathValue("run_id"), false); err != nil {
		return reply{}, err
	}
	return ok(pyjson.Member{Name: "cancellation_requested", Value: jsonBool(true)}), nil
}

func (h *HTTP) deleteRun(ctx context.Context, p principal.Principal, r *http.Request, _ http.ResponseWriter) (reply, error) {
	n, err := h.Service.DeleteRuns(ctx, p.UserID, []string{r.PathValue("run_id")})
	if err != nil {
		return reply{}, err
	}
	return ok(pyjson.Member{Name: "deleted", Value: jsontext.Value(itoa(int64(n)))}), nil
}

func (h *HTTP) clearRuns(ctx context.Context, p principal.Principal, _ *http.Request, _ http.ResponseWriter) (reply, error) {
	n, err := h.Service.DeleteRuns(ctx, p.UserID, nil)
	if err != nil {
		return reply{}, err
	}
	return ok(pyjson.Member{Name: "deleted", Value: jsontext.Value(itoa(int64(n)))}), nil
}

// SaveRunbook is save_runbook for the user.
func (s *Service) SaveRunbook(ctx context.Context, userID int64, v jsontext.Value) (Runbook, error) {
	book, err := NormalizeRunbook(v)
	if err != nil {
		return Runbook{}, err
	}
	idV, hasID := pyjson.Get(v, "id")
	hadID := hasID && string(idV) != `""`
	err = s.o.DB.Write(ctx, func(tx *store.Tx) error {
		books, err := readRunbooks(ctx, tx, userID)
		if err != nil {
			return err
		}
		next, err := saveRunbook(books, book, hadID)
		if err != nil {
			return err
		}
		return WriteRunbooksTx(ctx, tx, userID, next)
	})
	return book, storageErr(err)
}

// DeleteRunbook is delete_runbook.
func (s *Service) DeleteRunbook(ctx context.Context, userID int64, id string) error {
	return storageErr(s.o.DB.Write(ctx, func(tx *store.Tx) error {
		books, err := readRunbooks(ctx, tx, userID)
		if err != nil {
			return err
		}
		n := len(books)
		books = slicesDelete(books, id)
		if len(books) == n {
			return Fail("not_found")
		}
		return WriteRunbooksTx(ctx, tx, userID, books)
	}))
}

func (h *HTTP) state(ctx context.Context, p principal.Principal, _ *http.Request, _ http.ResponseWriter) (reply, error) {
	out, err := h.Service.State(ctx, p.UserID)
	return reply{http.StatusOK, out}, err
}
