package terminal

import (
	"context"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// SavedRoutes resolves the saved jump host or SOCKS5 proxy a connection
// typed by hand refers to (provided by internal/hosts). Both fail with
// fault.NotFound for an entry that does not exist or belongs to another
// user. Neither carries a password: the terminal adds it.
type SavedRoutes interface {
	JumpHost(ctx context.Context, owner int64, jumpHostID string) (client.Hop, error)
	SOCKSProxy(ctx context.Context, owner int64, socksProxyID string) (client.SOCKS, error)
}

// usernamePattern is USERNAME_PATTERN of app/profile_manager.py.
var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9_\-.]{1,32}$`)

// maxHostLen bounds a typed host before the dialer canonicalizes it.
const maxHostLen = 253

func invalid(msg string) error { return fault.New(fault.InvalidValue, msg) }

// resolve turns the request into a dial target for owner. A profile is
// resolved server-side; of the typed fields only the password typed for
// this attempt is used then. A connection typed by hand is checked like
// _validate_ssh_params of the Python release.
func (m *Manager) resolve(ctx context.Context, owner int64, req protocol.OpenTarget) (client.Target, error) {
	if req.ProfileID != "" {
		if m.profiles == nil {
			return client.Target{}, fault.New(fault.NotAvailableInPreview, "")
		}
		t, err := m.profiles.Resolve(ctx, owner, req.ProfileID)
		if err != nil {
			return client.Target{}, err
		}
		t.Owner = owner
		t.Display.ProfileID = req.ProfileID
		if t.Hop.Auth.Password == "" && t.Hop.Auth.KeyID == "" {
			t.Hop.Auth.Password = req.Password
			if req.SavedPassword {
				if t.Hop.Auth.Password, err = m.savedPassword(ctx, owner, req.ProfileID); err != nil {
					return client.Target{}, err
				}
			}
		}
		if err := m.addRouteSecrets(ctx, owner, &t, req); err != nil {
			return client.Target{}, err
		}
		return t, nil
	}
	host := strings.TrimSpace(req.Host)
	user := strings.TrimSpace(req.Username)
	port := req.Port
	if port == 0 {
		port = 22
	}
	switch {
	case host == "":
		return client.Target{}, invalid("Host is required.")
	case len(host) > maxHostLen:
		return client.Target{}, invalid("Invalid host format.")
	case req.JumpHostID != "" && req.SOCKSProxyID != "":
		return client.Target{}, invalid("A host can use either a jump host or a SOCKS5 proxy, not both.")
	}
	// A user:target selector (SSH gateway) or Tailscale SSH needs the
	// variant provider; the selector itself is checked there.
	t, variant, err := m.typedVariant(req, host, user, port, owner)
	if err != nil {
		return client.Target{}, err
	}
	if !variant {
		switch {
		case user == "":
			return client.Target{}, invalid("Username is required.")
		case !usernamePattern.MatchString(user):
			return client.Target{}, invalid("Invalid username format.")
		case req.SavedPassword:
			// A saved password belongs to a saved host (internal/vault).
			return client.Target{}, errSavedPasswords
		case req.AuthType == protocol.AuthPassword && req.Password == "":
			return client.Target{}, invalid("Password required.")
		case req.AuthType == protocol.AuthKey && req.KeyID == "":
			return client.Target{}, invalid("Password or SSH key required.")
		}
		t = client.Target{Owner: owner, Hop: client.Hop{Host: host, Port: port, User: user}}
		if req.AuthType == protocol.AuthKey {
			t.Hop.Auth.KeyID = req.KeyID
		} else {
			t.Hop.Auth.Password = req.Password
		}
	}
	if req.JumpHostID == "" && req.SOCKSProxyID == "" {
		return t, nil
	}
	if m.routes == nil {
		return client.Target{}, fault.New(fault.NotAvailableInPreview, "")
	}
	if req.JumpHostID != "" {
		j, err := m.routes.JumpHost(ctx, owner, req.JumpHostID)
		if err != nil {
			return client.Target{}, err
		}
		t.Jumps = []client.Hop{j}
		t.Display.JumpHostID = req.JumpHostID
	} else {
		p, err := m.routes.SOCKSProxy(ctx, owner, req.SOCKSProxyID)
		if err != nil {
			return client.Target{}, err
		}
		t.Proxy = &p
		t.Display.SOCKSProxyID = req.SOCKSProxyID
	}
	if err := m.addRouteSecrets(ctx, owner, &t, req); err != nil {
		return client.Target{}, err
	}
	return t, nil
}

// sessionInfo describes a new session as ssh_connected did.
func sessionInfo(t client.Target) protocol.SessionInfo {
	info := protocol.SessionInfo{
		Host: t.Hop.Host, Port: t.Hop.Port, Username: t.Hop.User, AuthType: protocol.AuthPassword,
		KeyID: t.Hop.Auth.KeyID, ProfileID: t.Display.ProfileID,
		JumpHostID: t.Display.JumpHostID, SOCKSProxyID: t.Display.SOCKSProxyID,
		ViaSOCKS: t.Proxy != nil, ReconnectRouteKnown: true,
	}
	switch {
	case t.Display.Tailscale:
		info.AuthType = protocol.AuthTailscale
	case t.Hop.Auth.KeyID != "":
		info.AuthType = protocol.AuthKey
	}
	if len(t.Jumps) > 0 {
		info.ViaJump = t.Jumps[0].Host
	}
	return info
}

// previewNotice is written to the terminal when the profile asks for
// something M1 does not run: Herdr or startup commands.
const previewNotice = "\r\n\x1b[33mWebSSH preview: Herdr and startup commands are not run yet.\x1b[0m\r\n"

func notice(t client.Target, _ protocol.OpenTarget) []byte {
	if t.Display.UseHerdr || t.Display.StartupCommand {
		return []byte(previewNotice)
	}
	return nil
}

// maxDisplayName is the length of a display name in characters, as the
// Python release cut it.
const maxDisplayName = 128

// displayName applies Python's name.strip()[:128]: whitespace as
// str.isspace counts it, length in code points. Invalid UTF-8 becomes
// U+FFFD, so the stored name is valid text.
func displayName(name string) string {
	name = strings.ToValidUTF8(name, "�")
	name = strings.TrimFunc(name, func(r rune) bool { return unicode.IsSpace(r) || r >= 0x1c && r <= 0x1f })
	if utf8.RuneCountInString(name) > maxDisplayName {
		name = string([]rune(name)[:maxDisplayName])
	}
	return name
}
