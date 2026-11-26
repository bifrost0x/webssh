package principal

import "slices"

// Action names an operation that needs a fresh step-up grant. A grant is
// bound to the user, the session, the action and the target, and it is
// consumed by exactly one operation (ADR 0011). The catalog is closed: a
// new action is added here in a contract change, never as a free string.
type Action string

// Step-up actions of M1.
const (
	ActionKeyUpload             Action = "key.upload"
	ActionKeyReplace            Action = "key.replace"
	ActionKeyDelete             Action = "key.delete"
	ActionHostKeyDelete         Action = "host_key.delete"
	ActionTOTPEnroll            Action = "totp.enroll"
	ActionTOTPDelete            Action = "totp.delete"
	ActionPasskeyEnroll         Action = "passkey.enroll"
	ActionPasskeyDelete         Action = "passkey.delete"
	ActionMFAEnable             Action = "mfa.enable"
	ActionMFADisable            Action = "mfa.disable"
	ActionRecoveryRotate        Action = "recovery.rotate"
	ActionSecurityFeatureUpdate Action = "security_feature.update"
	ActionUserCreate            Action = "user.create"
)

// m1Actions are the actions of M1; the catalog is m1Actions followed by
// the lists of the M2 contracts (action_*.go).
var m1Actions = []Action{
	ActionKeyUpload, ActionKeyReplace, ActionKeyDelete, ActionHostKeyDelete,
	ActionTOTPEnroll, ActionTOTPDelete, ActionPasskeyEnroll, ActionPasskeyDelete,
	ActionMFAEnable, ActionMFADisable, ActionRecoveryRotate,
	ActionSecurityFeatureUpdate, ActionUserCreate,
}

var actions = slices.Concat(m1Actions, identityActions, operationActions)

// Actions returns the catalog.
func Actions() []Action {
	return slices.Clone(actions)
}

// Known reports whether a is in the catalog.
func (a Action) Known() bool {
	return slices.Contains(actions, a)
}
