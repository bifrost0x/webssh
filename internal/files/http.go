package files

import (
	"net/http"

	"github.com/bifrost0x/webssh/internal/principal"
)

// HandoffHTTP serves the parked answers (HandoffPath, a user route).
func (s *Service) HandoffHTTP(w http.ResponseWriter, r *http.Request) {
	p, err := principal.Require(r.Context())
	body, ok := []byte(nil), false
	if err == nil {
		body, ok = s.handoff.take(p, r.PathValue("token"))
	}
	w.Header().Set("Cache-Control", "no-store")
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"success":false,"code":"SOURCE_UNAVAILABLE","error":"The file is no longer available. Open it again."}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}
