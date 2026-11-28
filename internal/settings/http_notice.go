package settings

import (
	"context"
	"net/http"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

type noticesResponse struct {
	Notices []string `json:"notices"`
}

// notices answers GET /api/account/notices with the pending notices of
// the signed-in account.
func (h *HTTP) notices(ctx context.Context, p principal.Principal, _ *http.Request) (any, error) {
	pending, err := h.Settings.Notices(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	return noticesResponse{Notices: pending}, nil
}

// acknowledgeNotice answers POST /api/account/notices/acknowledge with the
// body {"notice": <id>}. It acts on the signed-in account only; the body
// has no member that could name another one.
func (h *HTTP) acknowledgeNotice(ctx context.Context, p principal.Principal, r *http.Request) (any, error) {
	body, err := readObject(r, msgInvalidNotice)
	if err != nil {
		return nil, err
	}
	notice, ok := asString(body["notice"])
	if len(body) != 1 || !ok || !in(Notices, notice) {
		return nil, fault.New(fault.InvalidRequest, msgInvalidNotice)
	}
	pending, err := h.Settings.AcknowledgeNotice(ctx, p.UserID, notice)
	if err != nil {
		return nil, saveFault(err, msgNoticeNotSaved)
	}
	return noticesResponse{Notices: pending}, nil
}
