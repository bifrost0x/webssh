package gateway

import (
	"context"
	"slices"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/fault"
)

const (
	methodPublicKey   = "publickey"
	methodPassword    = "password"
	methodInteractive = "keyboard-interactive"

	maxAuthSteps        = 8
	maxInteractiveRound = 8
)

// Authentication refusals, with the texts of the Python release.
var (
	// ErrAuthFailed ends the authentication without a further method.
	ErrAuthFailed = fault.New(fault.AuthFailed, "Gateway authentication failed")
	// ErrFactorRejected means the server rejected answered prompts. The
	// saved password is never sent afterwards, so it cannot be tried as an
	// OTP replacement.
	ErrFactorRejected = fault.New(fault.AuthFailed, "Gateway authentication did not complete")
	errNoMethod       = fault.New(fault.AuthFailed, "No supported SSH authentication method")
	errAuthLimit      = fault.New(fault.AuthFailed, "Gateway authentication limit exceeded")
	errBadResponse    = fault.New(fault.AuthFailed, "Invalid authentication response")
)

// Challenger asks the browser one keyboard-interactive round.
type Challenger interface {
	Challenge(ctx context.Context, title, instructions string, prompts []Prompt) ([]string, error)
}

// Credentials are the saved factors of the hop. An empty Password means
// "ask the browser"; it is dropped after its one use.
type Credentials struct {
	Signer   ssh.Signer
	Password string
}

// Auth chooses methods for multi-factor gateway and MFA logins. It is a
// ssh.ClientAuthCallback, the x/crypto hook that runs before every
// authentication attempt after "none" with the server's allowed methods
// and the methods that failed or partially succeeded so far. Use it for
// one connection only.
//
// Order, as in Python's GatewayAuthStrategy:
//   - a key goes first;
//   - with a saved password and an ordinary username, keyboard-interactive
//     is preferred when offered (PAM often needs several answers), and the
//     password is a fallback only if keyboard-interactive fails before any
//     prompt was shown;
//   - after a partial success the next untried of password and
//     keyboard-interactive follows;
//   - a "failure" that removes the used method from the allowed list
//     counts as accepted (Warpgate), except after answered prompts;
//   - any rejected factor ends the attempt; no method runs twice.
type Auth struct {
	ctx      context.Context
	username string
	creds    Credentials
	ask      Challenger
	check    func() error

	mu               sync.Mutex
	attempted        map[string]bool
	last             string
	triedBefore      int
	steps            int
	rounds           int
	promptlessFallbk bool
	promptErr        error // why the browser side failed; x/crypto drops it
}

// NewAuth binds the policy to ctx: cancelling ctx aborts a pending prompt.
// check, if not nil, runs before every method; its error ends the
// authentication (the gateway was switched off).
func NewAuth(ctx context.Context, username string, creds Credentials, ask Challenger, check func() error) *Auth {
	return &Auth{ctx: ctx, username: username, creds: creds, ask: ask, check: check, attempted: map[string]bool{}}
}

// Callback implements ssh.ClientAuthCallback.
func (a *Auth) Callback(c *ssh.ClientAuthContext) (ssh.AuthMethod, error) {
	if err := a.ctx.Err(); err != nil {
		return nil, ErrCancelled
	}
	if a.check != nil {
		if err := a.check(); err != nil {
			return nil, err
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.promptErr != nil {
		return nil, a.promptErr
	}
	a.steps++
	if a.steps > maxAuthSteps {
		return nil, errAuthLimit
	}
	allowed := c.AllowedMethods
	failed := a.last != "" && len(c.TriedMethods) > a.triedBefore
	if failed && !slices.Contains(allowed, a.last) && !(a.last == methodInteractive && a.rounds > 0) {
		// Warpgate accepts a factor by answering "failure" without the
		// partial-success flag and drops that method from the list.
		// Paramiko reports this as BadAuthenticationType and Python
		// continues with the remaining methods; so does this policy.
		failed = false
	}
	if failed {
		// The previous method was rejected.
		if a.last == methodInteractive && a.rounds == 0 && a.promptlessFallbk &&
			slices.Contains(allowed, methodPassword) && !a.attempted[methodPassword] {
			return a.use(methodPassword, c), nil
		}
		if a.last == methodInteractive && a.rounds > 0 {
			return nil, ErrFactorRejected
		}
		return nil, ErrAuthFailed
	}
	if a.last == "" {
		if m, err := a.initial(allowed); err != nil {
			return nil, err
		} else if m != "" {
			return a.use(m, c), nil
		}
	}
	for _, m := range []string{methodPassword, methodInteractive} {
		if slices.Contains(allowed, m) && !a.attempted[m] {
			return a.use(m, c), nil
		}
	}
	return nil, ErrAuthFailed
}

// initial picks the first method after "none". An empty result means the
// preferred method is not offered and the normal order applies.
func (a *Auth) initial(allowed []string) (string, error) {
	switch {
	case a.creds.Signer != nil:
		return pick(methodPublicKey, allowed), nil
	case a.creds.Password != "" && !IsSelector(a.username):
		switch {
		case slices.Contains(allowed, methodInteractive):
			a.promptlessFallbk = slices.Contains(allowed, methodPassword)
			return methodInteractive, nil
		case slices.Contains(allowed, methodPassword):
			return methodPassword, nil
		}
		return "", errNoMethod
	case a.creds.Password != "":
		return pick(methodPassword, allowed), nil
	default:
		return pick(methodInteractive, allowed), nil
	}
}

func pick(m string, allowed []string) string {
	if slices.Contains(allowed, m) {
		return m
	}
	return ""
}

func (a *Auth) use(m string, c *ssh.ClientAuthContext) ssh.AuthMethod {
	a.attempted[m] = true
	a.last = m
	a.triedBefore = len(c.TriedMethods)
	switch m {
	case methodPublicKey:
		return ssh.PublicKeys(a.creds.Signer)
	case methodPassword:
		return ssh.PasswordCallback(a.password)
	default:
		return ssh.KeyboardInteractive(a.interactive)
	}
}

// password returns the saved password once, or asks the browser for it.
// Called by x/crypto without a.mu held.
func (a *Auth) password() (string, error) {
	a.mu.Lock()
	saved := a.creds.Password
	a.creds.Password = ""
	a.mu.Unlock()
	if saved != "" {
		return saved, nil
	}
	answers, err := a.ask.Challenge(a.ctx, "", "", []Prompt{{Label: "Password"}})
	if err == nil && len(answers) != 1 {
		err = errBadResponse
	}
	if err != nil {
		return "", a.fail(err)
	}
	return answers[0], nil
}

// interactive forwards each keyboard-interactive round to the browser. The
// saved password is never used to answer a prompt.
func (a *Auth) interactive(name, instruction string, questions []string, echos []bool) ([]string, error) {
	a.mu.Lock()
	a.rounds++
	rounds := a.rounds
	a.mu.Unlock()
	if rounds > maxInteractiveRound {
		return nil, a.fail(errAuthLimit)
	}
	if err := a.ctx.Err(); err != nil {
		return nil, a.fail(ErrCancelled)
	}
	prompts := make([]Prompt, len(questions))
	for i, q := range questions {
		prompts[i] = Prompt{Label: q, Echo: i < len(echos) && echos[i]}
	}
	answers, err := a.ask.Challenge(a.ctx, name, instruction, prompts)
	if err != nil {
		return nil, a.fail(err)
	}
	return answers, nil
}

func (a *Auth) fail(err error) error {
	a.mu.Lock()
	if a.promptErr == nil {
		a.promptErr = err
	}
	a.mu.Unlock()
	return err
}
