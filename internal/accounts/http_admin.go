package accounts

import (
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"io"
	"net/http"
	"strconv"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

// Gates says whether a security feature is active (internal/operations).
type Gates interface {
	Active(ctx context.Context, feature string) (bool, error)
}

// featureRecovery is the security feature of recovery codes.
const featureRecovery = "recovery"

// maxUserIDDigits bounds the path parameter; ids fit in an int64.
const maxUserIDDigits = 18

var (
	errInvalidRequest   = fault.New(fault.InvalidRequest, "Invalid request")
	errFeatureNotActive = fault.New(fault.NotFound, "")
)

// RegisterAdmin adds the account administration routes (lock, unlock,
// promote, demote, delete, MFA reset, recovery reset) relative to
// APPLICATION_ROOT. The edge mounts them behind the administrator
// session, CSRF and origin checks. As in the Python release, the step-up
// grant is checked before the account is looked up or the body is read.
func (h *HTTP) RegisterAdmin(mux *http.ServeMux) {
	mux.HandleFunc("POST /admin/api/users/{user_id}/{action}", h.serve(h.manage))
	mux.HandleFunc("DELETE /admin/api/users/{user_id}/mfa", h.serve(h.resetMFA))
	mux.HandleFunc("POST /admin/api/users/{user_id}/recovery", h.serve(h.resetRecovery))
}

// pathUserID reads the user id like Flask's int converter: digits only.
func pathUserID(r *http.Request) (int64, bool) {
	raw := r.PathValue("user_id")
	if raw == "" || len(raw) > maxUserIDDigits {
		return 0, false
	}
	for _, c := range raw {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	return id, err == nil
}

func (h *HTTP) consume(ctx context.Context, p principal.Principal, r *http.Request, action principal.Action, target string) error {
	if h.StepUp == nil {
		return fault.New(fault.StepUpRequired, "")
	}
	return h.StepUp.Consume(ctx, p, action, target, r.Header.Get(StepUpHeader))
}

func (h *HTTP) manage(ctx context.Context, p principal.Principal, r *http.Request) (int, any, error) {
	id, ok := pathUserID(r)
	if !ok {
		return 0, nil, errNotFound
	}
	action := r.PathValue("action")
	if err := h.consume(ctx, p, r, principal.ActionUserManage, strconv.FormatInt(id, 10)+":"+action); err != nil {
		return 0, nil, err
	}
	if action == ActionDelete {
		if err := h.Accounts.Delete(ctx, p, id); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{"ok": true}, nil
	}
	acc, err := h.Accounts.Manage(ctx, p, id, action)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"user": h.Accounts.userJSON(acc)}, nil
}

// readObject reads a bounded JSON object body. ok is false for anything
// else (request.get_json(silent=True) is not a dict).
func readObject(r *http.Request) (map[string]jsontext.Value, bool) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(raw) > maxBody {
		return nil, false
	}
	if jsontext.Value(raw).Kind() != '{' {
		return nil, false
	}
	var out map[string]jsontext.Value
	if json.Unmarshal(raw, &out) != nil {
		return nil, false
	}
	return out, true
}

// confirmation is data.get("confirm_username"): only a JSON string can
// equal a name.
func confirmation(body map[string]jsontext.Value) string {
	if v, ok := jsonString(body["confirm_username"]); ok {
		return v
	}
	// A value of any other type never matches; NUL cannot be in a name.
	return "\x00"
}

func (h *HTTP) resetMFA(ctx context.Context, p principal.Principal, r *http.Request) (int, any, error) {
	id, ok := pathUserID(r)
	if !ok {
		return 0, nil, errNotFound
	}
	if err := h.consume(ctx, p, r, principal.ActionUserMFAReset, strconv.FormatInt(id, 10)); err != nil {
		return 0, nil, err
	}
	body, ok := readObject(r)
	if !ok {
		return 0, nil, errInvalidRequest
	}
	if err := h.Accounts.ResetMFA(ctx, p, id, confirmation(body)); err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"ok": true}, nil
}

func (h *HTTP) resetRecovery(ctx context.Context, p principal.Principal, r *http.Request) (int, any, error) {
	id, ok := pathUserID(r)
	if !ok {
		return 0, nil, errNotFound
	}
	if err := h.consume(ctx, p, r, principal.ActionRecoveryReset, strconv.FormatInt(id, 10)); err != nil {
		return 0, nil, err
	}
	if h.Gates == nil {
		return 0, nil, errFeatureNotActive
	}
	on, err := h.Gates.Active(ctx, featureRecovery)
	if err != nil {
		return 0, nil, err
	}
	if !on {
		return 0, nil, errFeatureNotActive
	}
	body, _ := readObject(r) // json_object(): anything else is an empty object
	codes, err := h.Accounts.ReplaceRecovery(ctx, p, id, confirmation(body))
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"codes": codes}, nil
}
