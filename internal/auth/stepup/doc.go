// Package stepup is the one step-up service of WebSSH (ADR 0011). A user
// proves their identity again (password, TOTP or passkey) for one action of
// the closed catalog principal.Action and one target; the service issues a
// grant bound to user, session, action and target. A grant lives five
// minutes, like in the Python release, and is consumed by exactly one
// operation. A session that authenticated with MFA or a passkey within
// STEP_UP_MAX_AGE_SECONDS gets a grant without a new proof.
//
// Consumers declare
//
//	type StepUp interface {
//		Consume(ctx context.Context, p principal.Principal, action principal.Action, target, grant string) error
//	}
//
// and get the service from cmd/webssh. Both URL families (/api/step-up/…
// and /api/account/step-up/…) are served by this one service with one set
// of rules; they differ only in how the page carries the intent.
package stepup
