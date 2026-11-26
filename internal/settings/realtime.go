package settings

import (
	"context"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// settingSpec bounds the settings messages: tiny payloads that change
// stored state.
var settingSpec = protocol.Spec{MaxPayload: 256, Mutates: true}

// Routes returns the realtime routes of the account settings. Every
// result carries the value as stored, not as requested.
func (s *Service) Routes() []protocol.Route {
	return []protocol.Route{
		protocol.Handle(protocol.TypeSettingsTheme, settingSpec, s.setTheme),
		protocol.Handle(protocol.TypeSettingsConfirmClose, settingSpec, s.setConfirmClose),
		protocol.Handle(protocol.TypeSettingsDisconnect, settingSpec, s.setDisconnectAction),
	}
}

func (s *Service) setTheme(ctx context.Context, _ protocol.Peer, req protocol.SettingsTheme) (protocol.SettingsTheme, error) {
	u, err := s.realtimeUpdate(ctx, Changes{Theme: &req.Theme}, "Failed to save theme")
	return protocol.SettingsTheme{Theme: u.Theme}, err
}

// confirmCloseRequest is protocol.SettingsConfirmClose with the value
// required: Python refuses a missing or null value instead of storing
// false.
type confirmCloseRequest struct {
	Enabled *bool `json:"enabled"`
}

// Validate implements protocol.Validator.
func (r *confirmCloseRequest) Validate() error {
	if r.Enabled == nil {
		return invalid(msgInvalidConfirm)
	}
	return nil
}

func (s *Service) setConfirmClose(ctx context.Context, _ protocol.Peer, req confirmCloseRequest) (protocol.SettingsConfirmClose, error) {
	u, err := s.realtimeUpdate(ctx, Changes{ConfirmSessionClose: req.Enabled}, "Failed to save close confirmation setting")
	return protocol.SettingsConfirmClose{Enabled: u.ConfirmSessionClose}, err
}

func (s *Service) setDisconnectAction(ctx context.Context, _ protocol.Peer, req protocol.SettingsDisconnectAction) (protocol.SettingsDisconnectAction, error) {
	u, err := s.realtimeUpdate(ctx, Changes{DisconnectSessionAction: &req.Action}, "Failed to save disconnect session action")
	return protocol.SettingsDisconnectAction{Action: u.DisconnectSessionAction}, err
}

func (s *Service) realtimeUpdate(ctx context.Context, c Changes, failed string) (User, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return User{}, err
	}
	u, err := s.Update(ctx, p.UserID, c)
	if err != nil {
		return User{}, saveFault(err, failed)
	}
	return u, nil
}
