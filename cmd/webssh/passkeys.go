package main

import (
	"context"

	"github.com/bifrost0x/webssh/internal/auth/webauthn"
	"github.com/bifrost0x/webssh/internal/httpapi"
	"github.com/bifrost0x/webssh/internal/operations"
	"github.com/bifrost0x/webssh/internal/store"
)

// Passkeys join the build as an extension: prepare makes them a factor of
// MFA, step-up and the sign-in flow; wire hands the service the MFA and
// recovery services, which exist only after prepare, and adds the routes.
func init() {
	var svc *webauthn.Service
	register(extension{
		name:    "passkeys",
		schemas: []store.Schema{webauthn.Schema()},
		prepare: func(sys *system) error {
			cfg := sys.cfg
			svc = &webauthn.Service{DB: sys.db, Ring: sys.ring, Logger: sys.log,
				RP: webauthn.RelyingParty{ID: cfg.WebAuthn.RPID, Name: cfg.WebAuthn.RPName, Origin: cfg.WebAuthn.Origin}}
			opt := &sys.optional
			opt.passkeys = svc
			opt.passkeyFactor = webauthn.Factor{Service: svc}
			opt.passkeyCount = svc
			opt.passkeyTarget = svc.OwnsTarget
			opt.passkeyList = func(ctx context.Context, userID int64) ([]operations.Credential, error) {
				list, err := svc.List(ctx, userID)
				if err != nil {
					return nil, err
				}
				out := make([]operations.Credential, 0, len(list))
				for _, c := range list {
					out = append(out, operations.Credential{ID: c.ID, CreatedAt: isoTime(c.CreatedAt)})
				}
				return out, nil
			}
			if passkeyPlaceholder != nil {
				opt.passkeyPlaceholder = passkeyPlaceholder(svc)
			}
			opt.featureReady["passkey"] = operations.Readiness{Ready: true}
			return nil
		},
		wire: func(sys *system) error {
			svc.MFA = sys.mfa
			svc.Recovery = sys.recovery
			(&webauthn.HTTP{Service: svc, Gates: sys.gates, StepUp: sys.stepup, Pending: sys.flow.SignIn(), SignIn: sys.flow,
				Binding: httpapi.BrowserBinding, Limits: sys.factorLimits(), Audit: authAudit{sys.audit}, Logger: sys.log}).Register(sys.edge.Mux())
			return nil
		},
	})
}

// passkeyPlaceholder builds the end-to-end seed's passkey store; nil
// outside the end-to-end build.
var passkeyPlaceholder func(svc *webauthn.Service) func(ctx context.Context, userID int64, name, credentialID string, transports []string) error
