package client

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/fault"
)

// challenger is a prompts that also answers keyboard-interactive rounds.
type challenger struct {
	prompts
	mu      sync.Mutex
	rounds  []Challenge
	answers [][]string
	err     error
	wait    time.Duration
}

func (c *challenger) Challenge(ctx context.Context, q Challenge) ([]string, error) {
	c.mu.Lock()
	c.rounds = append(c.rounds, q)
	n := len(c.rounds)
	c.mu.Unlock()
	if c.wait > 0 {
		select {
		case <-time.After(c.wait):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if c.err != nil {
		return nil, c.err
	}
	if n > len(c.answers) {
		return nil, errors.New("no scripted answer")
	}
	return c.answers[n-1], nil
}

// The stored password answers the first hidden prompt, the user the one-
// time code; texts reach the user cleaned (C-CONN-09).
func TestChallengerAnswersFurtherRounds(t *testing.T) {
	cfg := kiServer([]string{"Password: ", "Verification code: \x1b[1m"}, []string{"pw", "123456"}, nil)
	cfg.PasswordCallback = nil
	s := startServer(t, cfg)
	d, _ := newDialer(trusting(s), nil)
	ix := &challenger{answers: [][]string{{"123456"}}}
	c, err := d.Dial(t.Context(), target(s, "u", Auth{Password: "pw"}), ix)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if len(ix.rounds) != 1 {
		t.Fatalf("rounds %+v", ix.rounds)
	}
	q := ix.rounds[0]
	if q.Role != RoleTarget || len(q.Questions) != 1 || q.Questions[0].Text != "Verification code: [1m" || q.Questions[0].Echo {
		t.Fatalf("round %+v", q)
	}
	// A hop still needs a password or a key, as in the Python release.
	ix = &challenger{answers: [][]string{{"pw"}, {"123456"}}}
	if c, err = d.Dial(t.Context(), target(s, "u", Auth{KeyID: ""}), ix); err == nil {
		_ = c.Close()
		t.Fatal("dial without any method passed validation")
	}
}

// A user answering every round of a hop without a password, also behind a
// jump host: each prompt names its hop.
func TestChallengerPerHop(t *testing.T) {
	cfg := kiServer([]string{"Code: "}, []string{"42"}, nil)
	cfg.PasswordCallback = func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
		if string(p) == "pw" {
			return nil, nil
		}
		return nil, errors.New("no")
	}
	jump := startServer(t, cfg)
	innerCfg := kiServer([]string{"Password: ", "Token: "}, []string{"unused", "7"}, nil)
	innerCfg.PasswordCallback = nil
	inner := startServer(t, innerCfg)
	d, _ := newDialer(trusting(jump, inner), nil)
	tgt := target(inner, "u", Auth{Password: "unused"})
	tgt.Jumps = []Hop{target(jump, "u", Auth{Password: "pw"}).Hop}
	ix := &challenger{answers: [][]string{{"7"}}}
	c, err := d.Dial(t.Context(), tgt, ix)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if len(ix.rounds) != 1 || ix.rounds[0].Role != RoleTarget || ix.rounds[0].Questions[0].Text != "Token:" {
		t.Fatalf("rounds %+v", ix.rounds)
	}
}

// K8 and M7 with a user in the loop: after a rejected answer nothing else
// is tried, the password is never sent, and the user's decline or a
// wrong answer ends the attempt with auth_failed.
func TestChallengerRejectedAnswerEndsTheAttempt(t *testing.T) {
	passwordCalls := 0
	cfg := kiServer([]string{"Password: ", "Code: "}, []string{"pw", "1"}, &passwordCalls)
	s := startServer(t, cfg)
	d, _ := newDialer(trusting(s), nil)
	ix := &challenger{answers: [][]string{{"wrong"}, {"wrong"}}}
	_, err := d.Dial(t.Context(), target(s, "u", Auth{}), ix)
	if err == nil {
		t.Fatal("dial without a method")
	}
	// The password method is listed: the plan prefers it with a stored
	// password, and keyboard-interactive is not tried after it failed.
	ix = &challenger{answers: [][]string{{"9"}}}
	_, err = d.Dial(t.Context(), target(s, "u", Auth{Password: "pw"}), ix)
	if _, code := hopOf(t, err); code != fault.AuthFailed || passwordCalls != 1 || len(ix.rounds) != 0 {
		t.Fatalf("got %v, %d password attempts, %d rounds", err, passwordCalls, len(ix.rounds))
	}
	// keyboard-interactive only: a wrong code fails once, no retry.
	cfg.PasswordCallback = nil
	s = startServer(t, cfg)
	d, _ = newDialer(trusting(s), nil)
	ix = &challenger{answers: [][]string{{"9"}, {"9"}}}
	_, err = d.Dial(t.Context(), target(s, "u", Auth{Password: "pw"}), ix)
	if _, code := hopOf(t, err); code != fault.AuthFailed || len(ix.rounds) != 1 {
		t.Fatalf("wrong code: %v after %d rounds", err, len(ix.rounds))
	}
	ix = &challenger{err: errors.New("user cancelled")}
	_, err = d.Dial(t.Context(), target(s, "u", Auth{Password: "pw"}), ix)
	if _, code := hopOf(t, err); code != fault.AuthFailed {
		t.Fatalf("declined: %v", err)
	}
}

// The time the user takes is not part of the handshake budget.
func TestChallengerWaitIsNotTheHandshakeBudget(t *testing.T) {
	cfg := kiServer([]string{"Password: ", "Code: "}, []string{"pw", "5"}, nil)
	cfg.PasswordCallback = nil
	s := startServer(t, cfg)
	d, _ := newDialer(trusting(s), nil)
	d.HandshakeTimeout = 300 * time.Millisecond
	ix := &challenger{answers: [][]string{{"5"}}, wait: 600 * time.Millisecond}
	c, err := d.Dial(t.Context(), target(s, "u", Auth{Password: "pw"}), ix)
	if err != nil {
		t.Fatalf("slow answer: %v", err)
	}
	_ = c.Close()
}

// Remote texts are bounded, and too many questions are refused.
func TestChallengeBounds(t *testing.T) {
	long := strings.Repeat("ä", 2*maxQuestionChars)
	s := startServer(t, &ssh.ServerConfig{
		KeyboardInteractiveCallback: func(_ ssh.ConnMetadata, ask ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			if _, err := ask(long, long, []string{long}, []bool{true}); err != nil {
				return nil, err
			}
			qs := make([]string, maxQuestions+1)
			_, err := ask("", "", qs, make([]bool, len(qs)))
			return nil, err
		},
	})
	d, _ := newDialer(trusting(s), nil)
	ix := &challenger{answers: [][]string{{"a"}, make([]string, maxQuestions+1)}}
	_, err := d.Dial(t.Context(), target(s, "u", Auth{Password: "x"}), ix)
	if err == nil || len(ix.rounds) != 1 {
		t.Fatalf("got %v after %d rounds", err, len(ix.rounds))
	}
	q := ix.rounds[0]
	if len([]rune(q.Name)) != maxQuestionChars || len([]rune(q.Questions[0].Text)) != maxQuestionChars || !q.Questions[0].Echo {
		t.Fatalf("not bounded: %d %d", len([]rune(q.Name)), len([]rune(q.Questions[0].Text)))
	}
}
