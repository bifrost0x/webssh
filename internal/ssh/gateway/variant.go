package gateway

import (
	"context"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// Variant is the dialer variant of an attempt: every SSH hop, a jump host in
// front of the gateway included, authenticates with the gateway strategy
// (Auth) and asks the browser through a. With ready set, the target must
// pass the readiness probe before the connection is used, as a terminal
// through a gateway selector does; Quick SFTP runs OpenWithPrompts on the
// connection instead.
func (a *Attempt) Variant(ready bool) *client.Variant {
	v := &client.Variant{Auth: func(r client.AuthRequest) ssh.ClientAuthCallback {
		ask := hopChallenger{attempt: a, req: r}
		return NewAuth(r.Ctx, r.User, Credentials{Signer: r.Signer, Password: r.Password}, ask, a.Check).Callback
	}}
	if ready {
		v.Ready = func(ctx context.Context, target *ssh.Client) error {
			return PrepareTerminal(ctx, SSHSessions(target), a)
		}
	}
	return v
}

// hopChallenger asks the browser for one hop. The handshake watchdog is
// paused while the user answers. A jump host's prompts carry its name, as
// in the Python release.
type hopChallenger struct {
	attempt *Attempt
	req     client.AuthRequest
}

func (h hopChallenger) Challenge(ctx context.Context, title, instructions string, prompts []Prompt) ([]string, error) {
	if h.req.Role == client.RoleJump {
		var parts []string
		for _, p := range []string{title, instructions} {
			if p != "" {
				parts = append(parts, p)
			}
		}
		title, instructions = "Jump host: "+h.req.Host, strings.Join(parts, "\n")
	}
	if h.req.Pause != nil {
		resume := h.req.Pause()
		defer resume()
	}
	return h.attempt.Challenge(ctx, string(h.req.Role), title, instructions, prompts)
}
