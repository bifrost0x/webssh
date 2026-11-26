package client

import (
	"context"
	"errors"
	"slices"

	"golang.org/x/crypto/ssh"
)

// maxPromptRounds bounds keyboard-interactive rounds per hop, empty rounds
// included, so a server cannot keep a connection in authentication.
const maxPromptRounds = 8

// authPlan chooses the next method from what the server allows, as
// paramiko did for WebSSH: publickey with a stored key; the password
// method with a password; keyboard-interactive when the server does not
// accept the password method, where the password answers the first single
// hidden prompt, unless the password method already succeeded as one
// factor. No method runs twice. After a failed password or a
// rejected answer nothing else is tried, so a password is never sent to a
// server that already asked for and rejected it (servers such as Warpgate
// drop keyboard-interactive from the list after a rejected answer).
//
// Any further prompt (a one-time code, a second question) needs the user:
// an Interaction that is a Challenger gets the round, also for jump hosts;
// an attended connection without one ends with not_available_in_preview,
// an unattended one with interaction_required.
type authPlan struct {
	ctx      context.Context
	password string
	signer   ssh.Signer
	legacy   bool
	attended bool
	// ask puts a round to the user; nil without a Challenger.
	ask func(name, instruction string, questions []string, echos []bool) ([]string, error)

	rounds   int
	answered bool
	sha1Key  bool
	abort    error
}

func (a *authPlan) next(c *ssh.ClientAuthContext) (ssh.AuthMethod, error) {
	if a.abort != nil {
		return nil, a.abort
	}
	if err := a.ctx.Err(); err != nil {
		return nil, err
	}
	tried := func(m string) bool { return slices.Contains(c.TriedMethods, m) }
	// A password the server accepted as one factor is spent: it never
	// answers a later prompt, which asks for something else.
	if slices.Contains(c.PartialSuccessMethods, "password") {
		a.password = ""
	}
	done := func(m string) bool { return tried(m) || slices.Contains(c.PartialSuccessMethods, m) }
	allowed := func(m string) bool { return slices.Contains(c.AllowedMethods, m) && !done(m) }
	switch {
	case a.answered && tried("keyboard-interactive"), a.password != "" && tried("password"):
		return nil, errAuthExhausted
	case a.signer != nil && allowed("publickey"):
		signer, err := restrictSigner(a.signer, a.legacy)
		if err != nil {
			return nil, err
		}
		return ssh.PublicKeys(signer), nil
	case a.legacyRSARetry(c):
		// Some old servers advertise rsa-sha2-* in server-sig-algs but
		// accept only ssh-rsa. With the legacy setting the key is tried
		// once more with a SHA-1 signature.
		a.sha1Key = true
		signer, err := sha1Signer(a.signer)
		if err != nil {
			return nil, err
		}
		return ssh.PublicKeys(signer), nil
	case a.password != "" && allowed("password"):
		return ssh.Password(a.password), nil
	case a.password != "" && allowed("keyboard-interactive"):
		return ssh.KeyboardInteractive(a.challenge), nil
	case a.ask != nil && !a.answered && allowed("keyboard-interactive"):
		// No password, or another factor after one succeeded: the user
		// answers the rounds.
		return ssh.KeyboardInteractive(a.challenge), nil
	case len(c.PartialSuccessMethods) > 0 && (allowed("password") || allowed("keyboard-interactive")):
		// A factor succeeded and the server wants another one.
		return nil, a.needsUser()
	}
	return nil, errAuthExhausted
}

func (a *authPlan) needsUser() error {
	if a.attended {
		return errMultiStep
	}
	return errInteraction
}

func (a *authPlan) challenge(name, instruction string, questions []string, echos []bool) ([]string, error) {
	a.rounds++
	switch {
	case a.rounds > maxPromptRounds:
		a.abort = errAuthExhausted
	case len(echos) != len(questions):
		a.abort = errAuthExhausted
	case len(questions) == 0:
		// Servers send empty rounds (PAM info messages); they need no
		// answer.
		return []string{}, nil
	case !a.answered && a.password != "" && len(questions) == 1 && !echos[0]:
		// The stored password answers the first single hidden prompt.
		a.answered = true
		return []string{a.password}, nil
	case a.ask != nil:
		a.answered = true
		answers, err := a.ask(name, instruction, questions, echos)
		if err != nil {
			a.abort = err
			return nil, err
		}
		return answers, nil
	default:
		a.abort = a.needsUser()
	}
	return nil, a.abort
}

var errSignerAlgorithms = errors.New("the key cannot be restricted to safe signature algorithms")

// restrictSigner keeps an RSA key on SHA-2 signatures unless the hop has
// the legacy setting: x/crypto/ssh would otherwise fall back to ssh-rsa
// (SHA-1) for a server that does not send server-sig-algs. It fails
// closed: an RSA signer that cannot be restricted is not used.
func restrictSigner(s ssh.Signer, legacy bool) (ssh.Signer, error) {
	if !isRSA(s) {
		return s, nil
	}
	// x/crypto names the signature algorithms of a certificate signer by
	// those of the underlying key.
	algos := []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	if legacy {
		algos = append(algos, ssh.KeyAlgoRSA)
	}
	return withAlgorithms(s, algos)
}

// isRSA reports an RSA key or an RSA certificate.
func isRSA(s ssh.Signer) bool {
	t := s.PublicKey().Type()
	return t == ssh.KeyAlgoRSA || t == ssh.CertAlgoRSAv01
}

func sha1Signer(s ssh.Signer) (ssh.Signer, error) {
	return withAlgorithms(s, []string{ssh.KeyAlgoRSA})
}

func withAlgorithms(s ssh.Signer, algos []string) (ssh.Signer, error) {
	as, ok := s.(ssh.AlgorithmSigner)
	if !ok {
		return nil, errSignerAlgorithms
	}
	restricted, err := ssh.NewSignerWithAlgorithms(as, algos)
	if err != nil {
		return nil, errors.Join(errSignerAlgorithms, err)
	}
	return restricted, nil
}

func (a *authPlan) legacyRSARetry(c *ssh.ClientAuthContext) bool {
	return a.legacy && !a.sha1Key && a.signer != nil &&
		isRSA(a.signer) &&
		slices.Contains(c.AllowedMethods, "publickey") &&
		slices.Contains(c.TriedMethods, "publickey") &&
		!slices.Contains(c.PartialSuccessMethods, "publickey")
}
