package operations

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"io"
	"net/http"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

// SupportHTTP serves POST /api/account/support-report for every
// signed-in account (C-SUP-01). The report is an allowlisted snapshot;
// the page shows exactly the answer before it is copied or downloaded.
type SupportHTTP struct {
	Facts SupportFacts
	// HTTPS reports whether the request reached the server over HTTPS
	// (directly or through a trusted proxy).
	HTTPS func(*http.Request) bool
	Now   func() time.Time
}

// Register adds the route relative to APPLICATION_ROOT.
func (h *SupportHTTP) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/account/support-report", h.report)
}

func (h *SupportHTTP) report(w http.ResponseWriter, r *http.Request) {
	p, err := principal.Require(r.Context())
	if err != nil {
		status, code, message := fault.Status(err)
		writeJSON(w, status, errorBody(code, message))
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 4<<10))
	var req SupportRequest
	if err != nil || !stringMembers(raw) ||
		json.Unmarshal(raw, &req, json.RejectUnknownMembers(true)) != nil || req.Validate() != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Invalid report options"})
		return
	}
	now := time.Now
	if h.Now != nil {
		now = h.Now
	}
	writeJSON(w, http.StatusOK, BuildSupportReport(r.Context(), h.Facts, req, p.IsAdmin, h.HTTPS != nil && h.HTTPS(r), now()))
}

// stringMembers reports whether raw is an object whose members are all
// strings; null is not a string, as isinstance(value, str) says.
func stringMembers(raw []byte) bool {
	var members map[string]jsontext.Value
	if jsontext.Value(raw).Kind() != '{' || json.Unmarshal(raw, &members) != nil {
		return false
	}
	for _, v := range members {
		if v.Kind() != '"' {
			return false
		}
	}
	return true
}
