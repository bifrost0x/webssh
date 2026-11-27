package hostops

import (
	"bytes"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"io"
	"log/slog"
	"net/http"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/principal"
)

var (
	errCheckRate    = &apiError{http.StatusTooManyRequests, "busy", "Too many checks. Wait a minute and try again."}
	errCheckRunning = &apiError{http.StatusTooManyRequests, "busy", "A check is still running."}
	errChecksBusy   = &apiError{http.StatusTooManyRequests, "busy", "Other checks are running. Try again shortly."}
)

// ReachabilityHTTP serves POST /api/overview/reachability; the last answer
// (GET) is part of OverviewHTTP.
type ReachabilityHTTP struct {
	Check     *Reachability
	Permitted Permission
	Limiter   Limiter
	Accepting func() bool
	Logger    *slog.Logger
}

// Register adds the route to mux, relative to APPLICATION_ROOT.
func (h *ReachabilityHTTP) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/overview/reachability", serveAPI(h.Logger, h.run))
}

type checkRequest struct {
	IDs jsontext.Value `json:"ids"`
}

// wantedIDs reads ids: absent or null for every host, else at most
// MaxProbes strings of at most 128 characters.
func wantedIDs(raw jsontext.Value) (map[string]bool, error) {
	if len(raw) == 0 || raw.Kind() == 'n' {
		return nil, nil
	}
	var ids []jsontext.Value
	if raw.Kind() != '[' || json.Unmarshal(raw, &ids) != nil || len(ids) > MaxProbes {
		return nil, errInvalidBody
	}
	wanted := map[string]bool{}
	for _, v := range ids {
		var id string
		if v.Kind() != '"' || json.Unmarshal(v, &id) != nil || utf8.RuneCountInString(id) > 128 {
			return nil, errInvalidBody
		}
		wanted[id] = true
	}
	return wanted, nil
}

func (h *ReachabilityHTTP) run(r *http.Request, p principal.Principal) (int, any, error) {
	ctx := r.Context()
	if h.Accepting != nil && !h.Accepting() {
		return 0, nil, errNoWork
	}
	ids, err := requestedIDs(r)
	if err != nil {
		return 0, nil, err
	}
	wanted, err := wantedIDs(ids)
	if err != nil {
		return 0, nil, err
	}
	// D-27: the check is a permission of its own.
	if ok, err := h.Permitted(ctx, p); err != nil {
		return 0, nil, err
	} else if !ok {
		return 0, nil, errNotPermitted
	}
	body, err := h.Check.run(ctx, p.UserID, wanted, func(endpoints int) bool {
		return allowUser(h.Limiter, "overview_reachability", p.UserID, checkRateLimit, reachabilityRateSpan, 1) &&
			allowUser(h.Limiter, "overview_reachability_probes", p.UserID, probeBudget, reachabilityRateSpan, endpoints)
	}, h.Logger)
	return http.StatusOK, body, err
}

// requestedIDs reads the body as get_json(silent=True) does: no body,
// malformed JSON and null check every host; another value than an object
// is refused. Members other than ids are ignored.
func requestedIDs(r *http.Request) (jsontext.Value, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxScanBody+1))
	if err != nil || len(body) > maxScanBody {
		return nil, errInvalidBody
	}
	v := jsontext.Value(bytes.TrimSpace(body))
	if !v.IsValid() || v.Kind() == 'n' {
		return nil, nil
	}
	var req checkRequest
	if v.Kind() != '{' || json.Unmarshal(v, &req) != nil {
		return nil, errInvalidBody
	}
	return req.IDs, nil
}
