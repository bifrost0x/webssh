package stepup

import (
	"encoding/json/jsontext"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

// HTTP serves both step-up URL families on the one service: the account
// family (/api/account/step-up/…, intent tokens) for every signed-in user
// and the admin family (/api/step-up/…, action and target in every
// request) for administrators. The edge mounts it behind session, CSRF and
// origin checks.
type HTTP struct {
	Service *Service
	Limits  auth.Limits
	Logger  *slog.Logger
}

// Register adds the routes to mux, relative to APPLICATION_ROOT.
func (h *HTTP) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/account/step-up/intents", h.accountIntent)
	mux.HandleFunc("POST /api/account/step-up/password", h.accountProof(MethodPassword, "password", "password"))
	mux.HandleFunc("POST /api/account/step-up/totp", h.accountProof(MethodTOTP, "code", "totp"))
	mux.HandleFunc("POST /api/account/step-up/passkey/options", h.accountPasskeyOptions)
	mux.HandleFunc("POST /api/account/step-up/passkey/verify", h.accountProof(MethodPasskey, "", "passkey_verify"))
	mux.HandleFunc("POST /api/step-up/intents", h.adminIntent)
	mux.HandleFunc("POST /api/step-up/password", h.adminProof(MethodPassword, "password"))
	mux.HandleFunc("POST /api/step-up/totp", h.adminProof(MethodTOTP, "code"))
	mux.HandleFunc("POST /api/step-up/passkey/options", h.adminPasskeyOptions)
	mux.HandleFunc("POST /api/step-up/passkey/verify", h.adminPasskeyVerify)
}

const expiresIn = int(GrantTTL / time.Second)

func (h *HTTP) fail(w http.ResponseWriter, r *http.Request, err error) {
	auth.WriteError(w, r, h.Logger, err)
}

var integerTarget = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

// parseTarget reads "target" as the Python release accepts it: a string
// or an integer (its decimal form). An absent target is "".
func parseTarget(body auth.Object) (string, bool) {
	raw, ok := body["target"]
	if !ok {
		return "", true
	}
	switch raw.Kind() {
	case '"':
		s, ok := body.String("target")
		return s, ok && s != ""
	case '0':
		n := string(raw)
		if !integerTarget.MatchString(n) {
			return "", false
		}
		if n == "-0" {
			n = "0"
		}
		return n, true
	default:
		return "", false
	}
}

func readAction(body auth.Object) (principal.Action, string, bool) {
	name, _ := body.String("action")
	action := principal.Action(strings.TrimSpace(name))
	target, ok := parseTarget(body)
	return action, target, ok && action.Known()
}

// rateLimited answers RATELIMIT_REAUTH overruns like the Python routes.
func rateLimited() error {
	e := fault.New(fault.RateLimited, "Step-up authentication failed")
	e.RetryAfter = time.Minute
	return e
}

func (h *HTTP) accountIntent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := principal.Require(ctx)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	action, target, ok := readAction(auth.ReadObject(w, r))
	if !ok {
		h.fail(w, r, ErrInvalid)
		return
	}
	c, err := h.Service.Begin(ctx, p, action, target, ChannelAccount)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if c.Grant != "" {
		auth.WriteJSON(w, http.StatusOK, map[string]any{"grant": c.Grant, "expires_in": expiresIn, "method": MethodRecent})
		return
	}
	auth.WriteJSON(w, http.StatusOK, map[string]any{
		"intent": c.Intent, "required_assurance": string(c.Required), "preferred_method": c.Methods[0],
		"methods": c.Methods, "expires_in": expiresIn,
	})
}

func (h *HTTP) accountProof(method, field, limitKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		p, err := principal.Require(ctx)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		body := auth.ReadObject(w, r)
		token, ok := body.String("intent")
		if !ok || token == "" {
			h.fail(w, r, ErrFailed)
			return
		}
		if h.Limits.ReauthLimited(r, p.UserID, "account_step_up_"+limitKey) {
			h.fail(w, r, rateLimited())
			return
		}
		proof := Proof{Method: method, Credential: body["credential"]}
		if field != "" {
			proof.Secret, _ = body.String(field)
		}
		grant, err := h.Service.Prove(ctx, p, token, proof)
		if err != nil {
			if Rejected(err) {
				err = ErrFailed
			}
			h.fail(w, r, err)
			return
		}
		auth.WriteJSON(w, http.StatusOK, map[string]any{"grant": grant, "expires_in": expiresIn, "method": method})
	}
}

func (h *HTTP) accountPasskeyOptions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := principal.Require(ctx)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	token, ok := auth.ReadObject(w, r).String("intent")
	if !ok || token == "" {
		h.fail(w, r, ErrFailed)
		return
	}
	if h.Limits.ReauthLimited(r, p.UserID, "account_step_up_passkey_options") {
		h.fail(w, r, rateLimited())
		return
	}
	h.writeOptions(w, r, p, token)
}

func (h *HTTP) writeOptions(w http.ResponseWriter, r *http.Request, p principal.Principal, token string) {
	options, err := h.Service.PasskeyOptions(r.Context(), p, token)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	auth.WriteJSON(w, http.StatusOK, jsontext.Value(options))
}

// adminFailure maps service errors to the admin family's answers: an
// invalid request is step_up_failed with 400.
func adminFailure(err error) error {
	if fault.Is(err, fault.InvalidRequest) {
		return fault.New(fault.InvalidRequest, "Step-up authentication failed")
	}
	return err
}

func (h *HTTP) adminIntent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := principal.RequireAdmin(ctx)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	action, target, ok := readAction(auth.ReadObject(w, r))
	if !ok {
		h.fail(w, r, adminFailure(ErrInvalid))
		return
	}
	plan, _, err := h.Service.Plan(ctx, p, action, target, ChannelAdmin)
	if err != nil {
		h.fail(w, r, adminFailure(err))
		return
	}
	if plan.Grant != "" {
		auth.WriteJSON(w, http.StatusOK, map[string]any{"method": MethodRecent, "grant": plan.Grant})
		return
	}
	auth.WriteJSON(w, http.StatusOK, map[string]any{"method": plan.Methods[0], "methods": plan.Methods})
}

// writeRejected sends a wrong password or code the way the admin page
// retries it: 403 with code invalid_value. The fault catalog gives
// invalid_value 400, so this one answer is written here.
func writeRejected(w http.ResponseWriter) {
	auth.WriteJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": string(fault.InvalidValue), "error": "Step-up authentication failed"})
}

func (h *HTTP) adminProof(method, field string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		p, err := principal.RequireAdmin(ctx)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		body := auth.ReadObject(w, r)
		action, target, ok := readAction(body)
		if !ok {
			h.fail(w, r, adminFailure(ErrInvalid))
			return
		}
		if h.Limits.ReauthLimited(r, p.UserID, "admin_step_up_"+method) {
			h.fail(w, r, rateLimited())
			return
		}
		// The admin family always checks the proof it was sent.
		c, err := h.Service.BeginCeremony(ctx, p, action, target, ChannelAdmin)
		if err != nil {
			h.fail(w, r, adminFailure(err))
			return
		}
		secret, _ := body.String(field)
		grant, err := h.Service.Prove(ctx, p, c.Intent, Proof{Method: method, Secret: secret})
		switch {
		case Rejected(err):
			writeRejected(w)
		case err != nil:
			h.fail(w, r, adminFailure(err))
		default:
			auth.WriteJSON(w, http.StatusOK, map[string]any{"grant": grant, "expires_in": expiresIn})
		}
	}
}

func (h *HTTP) adminPasskeyOptions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := principal.RequireAdmin(ctx)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	action, target, ok := readAction(auth.ReadObject(w, r))
	if !ok {
		h.fail(w, r, adminFailure(ErrInvalid))
		return
	}
	c, err := h.Service.BeginCeremony(ctx, p, action, target, ChannelAdmin)
	if err != nil {
		h.fail(w, r, adminFailure(err))
		return
	}
	h.writeOptions(w, r, p, c.Intent)
}

func (h *HTTP) adminPasskeyVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := principal.RequireAdmin(ctx)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	body := auth.ReadObject(w, r)
	grant, err := h.Service.Prove(ctx, p, "", Proof{Method: MethodPasskey, Credential: body["credential"]})
	if err != nil {
		h.fail(w, r, ErrFailed)
		return
	}
	auth.WriteJSON(w, http.StatusOK, map[string]any{"grant": grant, "expires_in": expiresIn})
}
