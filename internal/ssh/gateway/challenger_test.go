package gateway

import (
	"context"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// attended is the terminal's interaction of an ordinary connection whose
// page answers prompts: host keys and banners are accepted here, the
// keyboard-interactive rounds go to the attempt.
type attended struct{ client.Challenger }

func (attended) HostKey(context.Context, client.HostKeyPrompt) (bool, error) { return true, nil }
func (attended) Banner(context.Context, client.BannerPrompt) (bool, error)   { return true, nil }

// An ordinary connection (no gateway switch) answers the second factor
// through prompt.interactive: the dialer's own plan sends the password,
// and the one-time code comes from the page (C-CONN-09).
func TestChallengerAnswersAnOrdinaryConnection(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	g, _ := newStandIn(t, "password+otp")
	b := newBrowser()
	b.answer = func(string, []Prompt) []string { return []string{g.otp} }
	a, actx := begin(t, ctx, b, false)
	d := &client.Dialer{Net: openNet{}, HostKeys: pinnedKeys{[]ssh.PublicKey{g.hostKey}}, Keys: keySource{}, Keepalive: -1}
	c, err := d.Dial(actx, client.Target{Owner: 7, Hop: client.Hop{Host: "127.0.0.1", Port: g.port, User: "alice",
		Auth: client.Auth{Password: g.password}}}, attended{a.Challenger()})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = c.Close()
	shown := b.challenges()
	if len(shown) != 1 || shown[0].Title != "Warpgate" || shown[0].Context != string(client.RoleTarget) ||
		len(shown[0].Prompts) != 1 || shown[0].Prompts[0].Echo {
		t.Fatalf("prompts %+v", shown)
	}
	if used := g.used(); len(used) != 2 || used[0] != "password" || used[1] != "keyboard-interactive" {
		t.Fatalf("methods %v", used)
	}
}

// A jump host's round carries its name as the title, as in the Python
// release, with the server's texts below it.
func TestChallengerNamesTheJumpHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	b := newBrowser()
	b.answer = func(string, []Prompt) []string { return []string{"x"} }
	a, actx := begin(t, ctx, b, false)
	answers, err := a.Challenger().Challenge(actx, client.Challenge{Role: client.RoleJump, Host: "bastion", Name: "PAM",
		Instruction: "Second factor", Questions: []client.Question{{Text: "Code:", Echo: true}}})
	if err != nil || len(answers) != 1 || answers[0] != "x" {
		t.Fatalf("answers %v %v", answers, err)
	}
	shown := b.challenges()
	if len(shown) != 1 || shown[0].Title != "Jump host: bastion" || shown[0].Instructions != "PAM\nSecond factor" ||
		!shown[0].Prompts[0].Echo || shown[0].Context != string(client.RoleJump) {
		t.Fatalf("prompts %+v", shown)
	}
}
