package terminal

import (
	"context"
	"crypto/subtle"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
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
		auth := client.Auth{Password: req.JumpPassword}
		if req.JumpSavedPassword {
			var err error
			resource := "jump:" + t.Display.JumpHostID
			if auth, err = m.savedAuth(ctx, func(ctx context.Context) (string, error) {
				return m.savedPassword(ctx, owner, resource)
			}); err != nil {
				return err
			}
		}
		if auth.Password == "" {
			return errJumpPassword
		}
		t.Jumps[0].Auth = auth
	}
	if t.Proxy != nil && t.Proxy.Username != "" {
		proxy := *t.Proxy
		auth := client.Auth{Password: req.SOCKSPassword}
		switch {
		case req.SOCKSSavedPassword && auth.Password != "":
			return errBothPasswords
		case req.SOCKSSavedPassword:
			var err error
			resource := "socks:" + t.Display.SOCKSProxyID
			if auth, err = m.savedAuth(ctx, func(ctx context.Context) (string, error) {
				return m.savedPassword(ctx, owner, resource)
			}); err != nil {
				return err
			}
		case auth.Password == "":
			return errSOCKSPassword
		}
		if auth.Password == "" || len(auth.Password) > maxSOCKSPassword {
			return errSOCKSLength
		}
		proxy.Password, proxy.Guard = auth.Password, auth.Guard
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

// targetPassword is the saved password of a typed target (credential_id
// and credential_target_token of terminal.open).
func (m *Manager) targetPassword(ctx context.Context, req protocol.OpenTarget, host string, port int, user string) (string, error) {
	if m.saved == nil {
		return "", errSavedPasswords
	}
	p, err := principal.Require(ctx)
	if err != nil {
		return "", err
	}
	if req.CredentialID == "" {
		return "", fault.New(fault.InvalidRequest, "")
	}
	return m.saved.TargetPassword(ctx, p, req.CredentialID, req.CredentialTargetToken, host, port, user, req.JumpHostID, req.SOCKSProxyID)
}

// savedAuth resolves a saved password and guards it: right before the
// dialer sends it, it is resolved again and must be unchanged, so an
// assignment, target or password that changed while the attempt waited on
// a prompt cancels it (CredentialGuard of the Python release).
func (m *Manager) savedAuth(ctx context.Context, fetch func(context.Context) (string, error)) (client.Auth, error) {
	pw, err := fetch(ctx)
	if err != nil {
		return client.Auth{}, err
	}
	return client.Auth{Password: pw, Guard: &savedGuard{fetch: fetch, want: pw}}, nil
}

type savedGuard struct {
	fetch func(context.Context) (string, error)
	want  string
}

func (g *savedGuard) Check(ctx context.Context) error {
	now, err := g.fetch(ctx)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(now), []byte(g.want)) != 1 {
		return fault.New(fault.CredentialTargetChanged, "")
	}
	return nil
}
