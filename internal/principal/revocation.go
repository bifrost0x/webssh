package principal

import "github.com/bifrost0x/webssh/internal/fault"

// Reason says why a browser session ended. The values are stable: they are
// written to the audit log and sent as the close reason of realtime
// connections.
type Reason string

// Reasons for ending a session.
const (
	ReasonLogout          Reason = "logout"           // the user signed out
	ReasonRevokedByUser   Reason = "revoked_by_user"  // the user ended the session in the session list
	ReasonPasswordChanged Reason = "password_changed" // all other sessions end on a password change
	ReasonFactorChanged   Reason = "factor_changed"   // second factors were reset
	ReasonAccountLocked   Reason = "account_locked"   // an administrator locked or removed the account
	ReasonRoleChanged     Reason = "role_changed"     // administrator rights were removed
	ReasonExpired         Reason = "expired"          // idle or absolute lifetime reached
	ReasonRecoveryEnded   Reason = "recovery_ended"   // the factor repair of a recovery session finished
	// ReasonDirectoryRefused: the directory check of an LDAP account failed
	// or the directory could not be reached (auth.Revalidator, fail closed).
	ReasonDirectoryRefused Reason = "directory_refused"
)

// Revocation announces that a session has ended. The session package
// publishes one Revocation per ended session after the change is
// committed and before the call that ended it returns; consumers such as
// the realtime endpoint close every connection of SessionID at once.
//
// An empty SessionID is an account-wide revocation: a lock, deletion or
// MFA reset of an account that had no session left. It names no
// connection; consumers that keep account resources beyond a session
// (terminals, persistent tmux sessions) end them by the reason's rules.
type Revocation struct {
	SessionID string
	UserID    int64
	Reason    Reason
}

// ErrRightsReduced is the refusal of a session check that fails only
// because the account lost the administrator rights the principal
// records. The session stays valid: a realtime connection closes with
// protocol.CloseRightsChanged and the page reconnects with a principal
// that has the account's current rights (RS8-R01). It unwraps to
// authentication_required; errors.Is matches only this value.
var ErrRightsReduced error = rightsReduced{}

type rightsReduced struct{}

func (rightsReduced) Error() string { return "administrator rights were removed" }

func (rightsReduced) Unwrap() error { return fault.New(fault.AuthenticationNeeded, "") }
