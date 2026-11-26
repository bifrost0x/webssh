package httpapi

import (
	"net/http"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// statusBody is what the realtime client asks after repeated failed
// connection attempts. A browser cannot read why an upgrade was refused,
// so this same-origin request tells it whether the session still holds
// and which schema the server speaks: 401 sends the page to the sign-in
// at once instead of retrying with backoff, a different schema makes it
// reload.
type statusBody struct {
	Success       bool     `json:"success"`
	Code          string   `json:"code,omitempty"`
	Error         string   `json:"error,omitempty"`
	Authenticated bool     `json:"authenticated"`
	Recovery      bool     `json:"recovery"`
	Schema        int      `json:"schema"`
	Subprotocols  []string `json:"subprotocols"`
}

// realtimeStatus answers GET /api/realtime/status. It reads the session
// like every other request and changes nothing.
func (h *Handler) realtimeStatus(w http.ResponseWriter, r *http.Request) {
	body := statusBody{
		Schema:       protocol.Version,
		Subprotocols: []string{protocol.Subprotocol(protocol.Version)},
	}
	p, ok := principal.From(r.Context())
	if !ok {
		status, code, message := fault.Status(errSignIn)
		body.Code, body.Error = string(code), message
		writeJSON(w, status, body)
		return
	}
	body.Success, body.Authenticated, body.Recovery = true, true, p.Recovery
	writeJSON(w, http.StatusOK, body)
}
