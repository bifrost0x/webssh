package settings

import (
	"context"
	"net/http"

	"github.com/bifrost0x/webssh/internal/principal"
)

func (h *HTTP) tourState(ctx context.Context, p principal.Principal, _ *http.Request) (any, error) {
	u, err := h.Settings.User(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	app, err := h.Settings.App(ctx)
	if err != nil {
		return nil, err
	}
	facts, err := h.tourFacts(ctx, app)
	if err != nil {
		return nil, err
	}
	resp := tourResponse{State: tourState(u), Administrator: p.IsAdmin}
	if p.IsAdmin {
		if h.Tour.AdminPanelEnabled {
			url := h.BasePath + "/admin"
			resp.AdminURL = &url
		}
		resp.ProcessRoot = h.Tour.ProcessRoot
	} else {
		// Users learn what they can use; where a value comes from and the
		// cookie and bootstrap settings are administrator information.
		kept := facts[:0]
		for _, f := range facts {
			if !in(tourAdminOnlyFacts, f.Key) {
				kept = append(kept, tourFact{Key: f.Key, Enabled: f.Enabled})
			}
		}
		facts = kept
	}
	resp.Facts = facts
	return resp, nil
}

func (h *HTTP) tourSave(ctx context.Context, p principal.Principal, r *http.Request) (any, error) {
	body, err := readObject(r, msgInvalidTourState)
	if err != nil {
		return nil, err
	}
	state, err := tourRequest(body)
	if err != nil {
		return nil, err
	}
	if _, err := h.Settings.Update(ctx, p.UserID, Changes{Tour: &state}); err != nil {
		return nil, saveFault(err, msgTourNotSaved)
	}
	return map[string]string{"state": state}, nil
}
