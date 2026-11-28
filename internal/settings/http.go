package settings

import (
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

// maxBody bounds a settings request; the largest one, a full overview
// arrangement with 100 acknowledged items, is far below it.
const maxBody = 64 << 10

// FeatureGates says whether a security feature (passkey, totp, oidc,
// ldap) is active: allowed by the environment, ready and switched on by
// an administrator. Provided by internal/operations.
type FeatureGates interface {
	FeatureActive(ctx context.Context, feature string) (bool, error)
}

// HTTP serves the settings routes of a signed-in account. The edge mounts
// it behind session, CSRF and origin checks; the principal comes from the
// request context.
type HTTP struct {
	Settings *Service
	Gates    FeatureGates
	// Tour holds the deployment facts of the introduction tour.
	Tour TourDeployment
	// BasePath is the path the application is reached under, for links.
	BasePath string
	Logger   *slog.Logger
}

// Register adds the routes to mux, relative to APPLICATION_ROOT.
func (h *HTTP) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/account/preferences", h.serve(h.preferences))
	mux.HandleFunc("GET /api/account/tour", h.serve(h.tourState))
	mux.HandleFunc("POST /api/account/tour", h.serve(h.tourSave))
	mux.HandleFunc("GET /api/account/notices", h.serve(h.notices))
	mux.HandleFunc("POST /api/account/notices/acknowledge", h.serve(h.acknowledgeNotice))
	mux.HandleFunc("PUT /api/overview/preferences", h.serve(h.overviewPreferences))
}

type handler func(ctx context.Context, p principal.Principal, r *http.Request) (any, error)

func (h *HTTP) serve(fn handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := principal.Require(r.Context())
		if err == nil {
			var body any
			if body, err = fn(r.Context(), p, r); err == nil {
				writeJSON(w, http.StatusOK, body)
				return
			}
		}
		status, code, message := fault.Status(err)
		if code == fault.Internal || code == fault.StorageError || code == fault.Unavailable {
			h.logger().ErrorContext(r.Context(), "settings request failed", "path", r.URL.Path, "error", err)
		}
		writeJSON(w, status, errorBody{Success: false, Code: string(code), Error: message})
	}
}

func (h *HTTP) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

type errorBody struct {
	Success bool   `json:"success"`
	Code    string `json:"code"`
	Error   string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, body, json.Deterministic(true))
}

// readObject reads a JSON object body. Like request.get_json(silent=True)
// of the Python release, a body that is not JSON (wrong media type,
// malformed, not an object) is refused with msg.
func readObject(r *http.Request, msg string) (map[string]jsontext.Value, error) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || (media != "application/json" && !jsonSuffix(media)) {
		return nil, fault.New(fault.InvalidRequest, msg)
	}
	raw, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxBody))
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			return nil, fault.New(fault.TooLarge, "")
		}
		return nil, fault.Wrap(fault.InvalidRequest, err, msg)
	}
	// json.loads semantics: the last of duplicate names wins.
	v, _, err := pythonLoad(raw)
	if err != nil {
		return nil, fault.New(fault.InvalidRequest, msg)
	}
	members, ok := asObject(v)
	if !ok {
		return nil, fault.New(fault.InvalidRequest, msg)
	}
	body := make(map[string]jsontext.Value, len(members))
	for _, m := range members {
		body[m.name] = m.value
	}
	return body, nil
}

// jsonSuffix is the structured syntax suffix Werkzeug accepts as JSON.
func jsonSuffix(media string) bool {
	return strings.HasPrefix(media, "application/") && strings.HasSuffix(media, "+json")
}

func (h *HTTP) preferences(ctx context.Context, p principal.Principal, r *http.Request) (any, error) {
	body, err := readObject(r, msgNothingToChange)
	if err != nil {
		return nil, err
	}
	c, err := parsePreferences(body)
	if err != nil {
		return nil, err
	}
	u, err := h.Settings.Update(ctx, p.UserID, c)
	if err != nil {
		return nil, saveFault(err, msgSettingsNotSaved)
	}
	return map[string]any{"settings": u.Document()}, nil
}

func (h *HTTP) overviewPreferences(ctx context.Context, p principal.Principal, r *http.Request) (any, error) {
	const msg = "Invalid request."
	body, err := readObject(r, msg)
	if err != nil {
		return nil, err
	}
	var c Changes
	for name, v := range body {
		switch name {
		case "panels":
			c.OverviewPanels = v
		case "dismissed":
			c.OverviewDismissed = v
		case "host_order":
			c.OverviewHostOrder = v
		default:
			return nil, fault.New(fault.InvalidRequest, msg)
		}
	}
	if len(body) == 0 {
		return nil, fault.New(fault.InvalidRequest, msg)
	}
	u, err := h.Settings.Update(ctx, p.UserID, c)
	if err != nil {
		return nil, overviewFault(err)
	}
	return u.overviewPreferences(), nil
}

// overviewFault gives failures of the overview preferences the codes of
// the Python route.
func overviewFault(err error) error {
	fe, ok := fault.From(err)
	switch {
	case ok && fe.Message == msgInvalidPanels:
		return fault.New(fault.InvalidLayout, msgInvalidPanels)
	case ok && fe.Message == msgInvalidDismissed:
		return fault.New(fault.InvalidDismissed, msgInvalidDismissed)
	case fault.Is(err, fault.StorageError):
		return fault.Wrap(fault.StorageFailed, err, msgOverviewNotSaved)
	}
	return err
}

// saveFault gives a storage failure the message of the Python release.
func saveFault(err error, msg string) error {
	if fault.Is(err, fault.StorageError) {
		return fault.Wrap(fault.StorageError, err, msg)
	}
	return err
}
