package realtime

import (
	"net/http"
	"strconv"
)

// LegacySocketIO answers the Socket.IO path of the Python release with 410
// Gone: the Go release speaks only the native WebSocket protocol (ADR
// 0005), and a page that still asks for it is outdated.
func LegacySocketIO() http.Handler {
	body := []byte(`{"success":false,"code":"version_unsupported","error":"Reload the page to use the current version."}`)
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusGone)
		_, _ = w.Write(body)
	})
}
