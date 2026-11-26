package hosts

import "context"

// Variants checks the SSH gateway and Tailscale SSH fields of a saved host
// (provided by cmd/webssh over internal/ssh/gateway and
// internal/ssh/tailscale). Without it both are refused as not available,
// as in M1.
type Variants interface {
	// GatewayEnabled fails while the administrator switch of the SSH
	// gateway is off. The error text is shown.
	GatewayEnabled(ctx context.Context) error
	// GatewaySelector checks the form of a "user:target" username. The
	// error text is shown.
	GatewaySelector(username string) error
	// TailscaleAccess is validate_tailscale_ssh_access for the signed-in
	// user of ctx: nil when the user may use the shared identity for host,
	// port and remote user now. The error text is shown.
	TailscaleAccess(ctx context.Context, host string, port int, remoteUser string) error
}

// variantRules are the checks validateProfile applies to the fields of the
// gateway and Tailscale SSH; nil refuses both.
type variantRules struct {
	ctx context.Context
	v   Variants
}

func (s *Service) variantRules(ctx context.Context) *variantRules {
	if s.Variants == nil {
		return nil
	}
	return &variantRules{ctx: ctx, v: s.Variants}
}

// tailscaleAuthorized is profile_is_authorized_for_launch: a saved
// Tailscale SSH host may be started by the signed-in user now.
func (s *Service) tailscaleAuthorized(ctx context.Context) func(r *record) bool {
	return func(r *record) bool {
		if s.Variants == nil {
			return false
		}
		port := int64(22)
		if v, ok := r.get("port"); ok {
			if n, isInt := asInt(v); isInt {
				port = n
			}
		}
		if port < 1 || port > 65535 {
			return false
		}
		return s.Variants.TailscaleAccess(ctx, r.text("host"), int(port), r.text("username")) == nil
	}
}
