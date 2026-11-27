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
		return NewAuth(r.Ctx, r.User, Credentials{Signer: r.Signer, Password: r.Password, Guard: r.Guard}, ask, a.Check).Callback
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
		title, instructions = jumpTitle(h.req.Host, title, instructions)
	}
	if h.req.Pause != nil {
		resume := h.req.Pause()
		defer resume()
	}
	return h.attempt.Challenge(ctx, string(h.req.Role), title, instructions, prompts)
}

// jumpTitle is the title of a jump host's round: the host's name, with
// the server's title and instructions below it.
func jumpTitle(host, title, instructions string) (string, string) {
	var parts []string
	for _, p := range []string{title, instructions} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return "Jump host: " + host, strings.Join(parts, "\n")
}

// Challenger returns the browser prompts of the attempt as the dialer's
// client.Challenger. An ordinary connection whose page answers prompts
// uses it, with an attempt begun with gateway false (GatewayAttempt with
// require_gateway=False): the dialer's own plan chooses the methods and
// puts the rounds it cannot answer to the user here (C-CONN-09). The
// dialer pauses its watchdog while the user answers.
func (a *Attempt) Challenger() client.Challenger { return attemptChallenger{a} }

type attemptChallenger struct{ a *Attempt }

func (c attemptChallenger) Challenge(ctx context.Context, q client.Challenge) ([]string, error) {
	prompts := make([]Prompt, len(q.Questions))
	for i, x := range q.Questions {
		prompts[i] = Prompt{Label: x.Text, Echo: x.Echo}
	}
	title, instructions := q.Name, q.Instruction
	if q.Role == client.RoleJump {
		title, instructions = jumpTitle(q.Host, title, instructions)
	}
	return c.a.Challenge(ctx, string(q.Role), title, instructions, prompts)
}
