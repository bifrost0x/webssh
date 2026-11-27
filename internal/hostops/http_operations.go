package hostops

import (
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

// maxOperationBody bounds a request body of the server operation routes.
const maxOperationBody = 64 << 10

// Operations serves the server operations of a connected session
// (C-OPS-04, C-OPS-05): reads for the session's owner, writes behind the
// server_operations_enabled switch with a one-use intent, the typed host
// for a reboot, a step-up bound to the intent and an audit record. The
// edge mounts it behind session, CSRF and origin checks.
type Operations struct {
	Sessions Sessions
	Switches Switches
	StepUp   StepUp
	Audit    Auditor
	Logger   *slog.Logger
	now      func() time.Time

	active  busySet
	intents intents

	mu   sync.Mutex
	runs map[*opRun]struct{}
}

// opRun is one running command; stop is closed when the caller's sign-in
// is revoked.
type opRun struct {
	p    principal.Principal
	stop chan struct{}
	once sync.Once
}

// Register adds the routes to mux, relative to APPLICATION_ROOT.
func (o *Operations) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/server-operations/{session_id}", o.serve(o.capabilities))
	mux.HandleFunc("POST /api/server-operations/read", o.serve(o.read))
	mux.HandleFunc("POST /api/server-operations/intents", o.serve(o.prepare))
	mux.HandleFunc("POST /api/server-operations/execute", o.serve(o.executeIntent))
}

// Revoked stops the commands of a revoked sign-in (subscriber of the
// session revocations), as login_cancellation_check did.
func (o *Operations) Revoked(rev principal.Revocation) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for r := range o.runs {
		if r.p.UserID == rev.UserID && (rev.SessionID == "" || rev.SessionID == r.p.SessionID) {
			r.once.Do(func() { close(r.stop) })
		}
	}
}

func (o *Operations) track(p principal.Principal) (*opRun, func()) {
	r := &opRun{p: p, stop: make(chan struct{})}
	o.mu.Lock()
	if o.runs == nil {
		o.runs = map[*opRun]struct{}{}
	}
	o.runs[r] = struct{}{}
	o.mu.Unlock()
	return r, func() {
		o.mu.Lock()
		delete(o.runs, r)
		o.mu.Unlock()
	}
}

func (o *Operations) clock() time.Time {
	if o.now != nil {
		return o.now()
	}
	return time.Now()
}

type opHandler func(ctx context.Context, p principal.Principal, r *http.Request) (any, error)

func (o *Operations) serve(fn opHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := principal.Require(r.Context())
		if err != nil {
			err = opErr("authentication_required")
		} else {
			var body any
			if body, err = fn(r.Context(), p, r); err == nil {
				writeOpJSON(w, http.StatusOK, body)
				return
			}
		}
		var oe *opError
		switch {
		case errors.As(err, &oe):
			writeOpJSON(w, opStatus(oe.code), map[string]string{"error": "Server operation could not be completed.", "code": oe.code})
		case fault.Is(err, fault.StepUpRequired):
			writeOpJSON(w, http.StatusForbidden, map[string]string{"error": "Reauthentication is required.", "code": "step_up_required"})
		default:
			o.logger().ErrorContext(r.Context(), "server operation failed", "path", r.URL.Path, "error", err)
			status, code, message := fault.Status(err)
			writeOpJSON(w, status, map[string]any{"success": false, "code": string(code), "error": message})
		}
	}
}

func (o *Operations) logger() *slog.Logger {
	if o.Logger != nil {
		return o.Logger
	}
	return slog.Default()
}

func writeOpJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, body)
}

// opRequest is the JSON object of a POST; any other body is
// invalid_request, as request.get_json(silent=True) gave Python.
type opRequest map[string]jsontext.Value

func readOpRequest(r *http.Request) (opRequest, error) {
	raw, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxOperationBody))
	if err != nil {
		return nil, opErr("invalid_request")
	}
	var req opRequest
	if jsontext.Value(raw).Kind() != '{' || json.Unmarshal(raw, &req) != nil {
		return nil, opErr("invalid_request")
	}
	return req, nil
}

func (q opRequest) str(name string) (string, bool) { return opTarget(q).str(name) }

// target is data.get("target", {}): a missing target is empty, anything
// but an object is invalid.
func (q opRequest) target() (opTarget, error) {
	raw, ok := q["target"]
	if !ok {
		return opTarget{}, nil
	}
	var t opTarget
	if raw.Kind() != '{' || json.Unmarshal(raw, &t) != nil {
		return nil, opErr("invalid_target")
	}
	return t, nil
}

// sudo is data.get("use_sudo", False), which must be a boolean.
func (q opRequest) sudo() (bool, error) {
	raw, ok := q["use_sudo"]
	if !ok {
		return false, nil
	}
	switch raw.Kind() {
	case 't':
		return true, nil
	case 'f':
		return false, nil
	}
	return false, opErr("invalid_target")
}

// command reads action, target and use_sudo and builds the command.
func (q opRequest) command(allowed []string) (string, opCommand, error) {
	action, ok := q.str("action")
	if !ok || !slices.Contains(allowed, action) {
		return "", opCommand{}, opErr("invalid_action")
	}
	target, err := q.target()
	if err != nil {
		return "", opCommand{}, err
	}
	sudo, err := q.sudo()
	if err != nil {
		return "", opCommand{}, err
	}
	c, err := buildCommand(action, target, sudo)
	return action, c, err
}

// owned is owned_session: the connected session of the caller.
func (o *Operations) owned(p principal.Principal, sessionID string, present bool) (Live, error) {
	if !present || sessionID == "" || len(sessionID) > 128 {
		return Live{}, opErr("unavailable")
	}
	live, ok := o.Sessions.Live(p.UserID, sessionID)
	if !ok {
		return Live{}, opErr("unavailable")
	}
	return live, nil
}

func (o *Operations) enabled(ctx context.Context) error {
	if o.Switches == nil || !o.Switches.ServerOperationsEnabled(ctx) {
		return opErr("disabled")
	}
	return nil
}

func (o *Operations) capabilities(ctx context.Context, p principal.Principal, r *http.Request) (any, error) {
	live, err := o.owned(p, r.PathValue("session_id"), true)
	if err != nil {
		return nil, err
	}
	enabled := o.Switches != nil && o.Switches.ServerOperationsEnabled(ctx)
	writes := []string{}
	if enabled {
		writes = writeActions
	}
	return map[string]any{
		"mutations_enabled": enabled, "host": live.Host, "username": live.Username,
		"read_actions": readActions, "write_actions": writes,
	}, nil
}

func (o *Operations) read(ctx context.Context, p principal.Principal, r *http.Request) (any, error) {
	q, err := readOpRequest(r)
	if err != nil {
		return nil, err
	}
	action, c, err := q.command(readActions)
	if err != nil {
		return nil, err
	}
	sessionID, present := q.str("session_id")
	live, err := o.owned(p, sessionID, present)
	if err != nil {
		return nil, err
	}
	run, untrack := o.track(p)
	defer untrack()
	res, err := o.execute(ctx, p.UserID, sessionID, live, c, false, run.stop)
	if err != nil {
		return nil, err
	}
	switch action {
	case "process.list":
		if res.Status == "completed" {
			if res.Processes, err = parseProcessList(res.Output); err != nil {
				return nil, err
			}
			res.Output = ""
		}
	case "container.logs":
		res.Output, res.ErrorOutput = newestContainerLogs(res.Output, res.ErrorOutput)
	}
	return res, nil
}

func (o *Operations) prepare(ctx context.Context, p principal.Principal, r *http.Request) (any, error) {
	if err := o.enabled(ctx); err != nil {
		return nil, err
	}
	q, err := readOpRequest(r)
	if err != nil {
		return nil, err
	}
	action, c, err := q.command(writeActions)
	if err != nil {
		return nil, err
	}
	sessionID, present := q.str("session_id")
	live, err := o.owned(p, sessionID, present)
	if err != nil {
		return nil, err
	}
	in := intent{userID: p.UserID, authID: p.SessionID, sessionID: sessionID, done: live.Done, action: action, cmd: c,
		host: live.Host, username: live.Username, expires: o.clock().Add(intentTTL)}
	if action == "system.reboot" {
		in.confirmation = live.Host
	}
	token, err := o.intents.add(in, o.clock())
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"intent": token, "action": action, "command": c.Text(), "host": live.Host, "username": live.Username,
		"confirmation": in.confirmation, "expires_in": int(intentTTL / time.Second),
	}, nil
}

// intent is get_intent with the check that the session is still the one
// the intent was prepared for.
func (o *Operations) intent(p principal.Principal, token string, consume bool) (intent, error) {
	in, err := o.intents.get(token, p.UserID, p.SessionID, o.clock(), consume)
	if err != nil {
		return intent{}, err
	}
	if live, ok := o.Sessions.Live(p.UserID, in.sessionID); !ok || live.Done != in.done {
		return intent{}, opErr("unavailable")
	}
	return in, nil
}

func (o *Operations) executeIntent(ctx context.Context, p principal.Principal, r *http.Request) (any, error) {
	if err := o.enabled(ctx); err != nil {
		return nil, err
	}
	q, err := readOpRequest(r)
	if err != nil {
		return nil, err
	}
	token, _ := q.str("intent")
	in, err := o.intent(p, token, false)
	if err != nil {
		return nil, err
	}
	if typed, _ := q.str("confirmation"); in.confirmation != "" && typed != in.confirmation {
		return nil, opErr("confirmation_required")
	}
	if o.StepUp == nil {
		return nil, fault.New(fault.StepUpRequired, "")
	}
	if err := o.StepUp.Consume(ctx, p, principal.ActionServerOperation, token, r.Header.Get(StepUpHeader)); err != nil {
		return nil, err
	}
	if in, err = o.intent(p, token, true); err != nil {
		return nil, err
	}
	o.audit("SERVER_OPERATION_REQUESTED", "action", in.action, "session_id", in.sessionID, "user", p.Username)
	run, untrack := o.track(p)
	defer untrack()
	res, err := o.execute(ctx, p.UserID, in.sessionID, Live{Done: in.done}, in.cmd, true, run.stop)
	if err != nil {
		outcome := "unavailable"
		if oe, ok := errors.AsType[*opError](err); ok {
			outcome = oe.code
		}
		o.audit("SERVER_OPERATION_RESULT", "action", in.action, "outcome", outcome, "user", p.Username)
		return nil, err
	}
	if in.action == "system.reboot" && res.Status == "completed" {
		res.Status = "requested"
	}
	o.audit("SERVER_OPERATION_RESULT", "action", in.action, "outcome", res.Status, "user", p.Username)
	return res, nil
}

func (o *Operations) audit(event string, kv ...any) {
	if o.Audit != nil {
		o.Audit.Security(event, kv...)
	}
}

// opStatus is the HTTP status of an operation error code.
func opStatus(code string) int {
	switch code {
	case "unavailable":
		return http.StatusNotFound
	case "authentication_required":
		return http.StatusUnauthorized
	case "disabled":
		return http.StatusForbidden
	case "busy":
		return http.StatusTooManyRequests
	case "invalid_intent", "unknown":
		return http.StatusConflict
	case "timeout":
		return http.StatusGatewayTimeout
	case "output_limit":
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}
