package auth

import (
	"net/http"

	"github.com/bifrost0x/webssh/internal/fault"
)

// msgRecoveryAfterPrimary is the answer of the retired stand-alone
// recovery sign-in.
const msgRecoveryAfterPrimary = "Complete the primary sign-in before using a Recovery Code"

// RegisterRecoveryCompat adds POST /login/recovery, the retired
// stand-alone recovery sign-in of older pages. Like the Python release it
// refuses every request without reading a code (a recovery code only
// completes a pending primary sign-in, POST /api/auth/recovery) and
// answers 404 while recovery codes are off.
func (h *FactorHTTP) RegisterRecoveryCompat(mux *http.ServeMux) {
	mux.HandleFunc("POST /login/recovery", func(w http.ResponseWriter, r *http.Request) {
		if !h.featureOn(w, r, FeatureRecovery) {
			return
		}
		h.fail(w, r, fault.New(fault.InvalidRequest, msgRecoveryAfterPrimary))
	})
}
