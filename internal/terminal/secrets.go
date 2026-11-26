package terminal

import (
	"context"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// maxSOCKSPassword is the RFC 1929 limit Python checked before connecting.
const maxSOCKSPassword = 255

// Messages of handle_ssh_connect in the Python release.
var (
	errJumpPassword   = invalid("Jump host password or SSH key required")
	errSOCKSPassword  = invalid("SOCKS5 proxy password required")
	errSOCKSLength    = invalid("SOCKS5 proxy password must contain 1 to 255 UTF-8 bytes")
	errBothPasswords  = fault.New(fault.InvalidRequest, "")
	errSavedPasswords = fault.New(fault.NotAvailableInPreview, "Saved passwords are not available in this preview.")
)

// addRouteSecrets gives a jump host with password sign-in and a SOCKS5
// proxy with a login their passwords: the one typed for this attempt or
// the saved one, as handle_ssh_connect did. A typed password for a route
// that does not sign in with one is ignored.
func (m *Manager) addRouteSecrets(ctx context.Context, owner int64, t *client.Target, req protocol.OpenTarget) error {
	if len(t.Jumps) > 0 && t.Jumps[0].Auth.KeyID == "" && t.Jumps[0].Auth.Password == "" {
		t.Jumps = append([]client.Hop(nil), t.Jumps...)
		pw := req.JumpPassword
		if req.JumpSavedPassword {
			var err error
			if pw, err = m.savedPassword(ctx, owner, "jump:"+t.Display.JumpHostID); err != nil {
				return err
			}
		}
		if pw == "" {
			return errJumpPassword
		}
		t.Jumps[0].Auth.Password = pw
	}
	if t.Proxy != nil && t.Proxy.Username != "" {
		proxy := *t.Proxy
		pw := req.SOCKSPassword
		switch {
		case req.SOCKSSavedPassword && pw != "":
			return errBothPasswords
		case req.SOCKSSavedPassword:
			var err error
			if pw, err = m.savedPassword(ctx, owner, "socks:"+t.Display.SOCKSProxyID); err != nil {
				return err
			}
		case pw == "":
			return errSOCKSPassword
		}
		if pw == "" || len(pw) > maxSOCKSPassword {
			return errSOCKSLength
		}
		proxy.Password = pw
		t.Proxy = &proxy
	}
	return nil
}

func (m *Manager) savedPassword(ctx context.Context, owner int64, resourceID string) (string, error) {
	if m.saved == nil {
		return "", errSavedPasswords
	}
	return m.saved.Password(ctx, owner, resourceID)
}
