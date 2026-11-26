package stepup

import "net/http"

// RegisterBootstrap adds POST /api/account/step-up/bootstrap, the proof
// with a bootstrap code (the route belongs to the area "github").
func (h *HTTP) RegisterBootstrap(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/account/step-up/bootstrap", h.accountProof(MethodBootstrap, "code", "bootstrap"))
}
