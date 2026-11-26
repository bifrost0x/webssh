package gateway

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

func answerOTP(code string) func(string, []Prompt) []string {
	return func(_ string, p []Prompt) []string {
		out := make([]string, len(p))
		for i := range p {
			out[i] = code
		}
		return out
	}
}

func TestGatewayKeyThenOTPWithInBandHostKeyQuestion(t *testing.T) {
	g, key := newStandIn(t, "key+otp")
	g.askHostKey = true
	b := newBrowser()
	b.answer = answerOTP(g.otp)
	typed := false
	b.onText = func(text string) string {
		if !typed && strings.Contains(text, "Trust it? [y/N]") {
			typed = true
			return "y"
		}
		return ""
	}
	a, ctx := begin(t, t.Context(), b, true)
	if _, err := dialVia(ctx, t, g, "alice@example.com:prod", client.Auth{}, key, a, true, nil); err != nil {
		t.Fatalf("dial: %v (output %q)", err, b.text())
	}
	if got := g.used(); !slices.Equal(got, []string{"publickey", "keyboard-interactive"}) {
		t.Fatalf("methods %v", got)
	}
	shown := b.challenges()
	if len(shown) != 1 || shown[0].Prompts[0].Label != "OTP: " || shown[0].Prompts[0].Echo ||
		shown[0].Context != "target" || shown[0].RequestID != "req-1" || len(shown[0].PromptID) != 32 ||
		shown[0].ExpiresIn < 1 || shown[0].ExpiresIn > 120 {
		t.Fatalf("challenges %+v", shown)
	}
	if !strings.Contains(b.text(), "Trust it?") {
		t.Fatalf("host-key question not shown: %q", b.text())
	}
}

func TestGatewayHostKeyDeclined(t *testing.T) {
	g, key := newStandIn(t, "key+otp")
	g.askHostKey = true
	b := newBrowser()
	b.answer = answerOTP(g.otp)
	b.onText = func(text string) string {
		if strings.HasSuffix(text, "[y/N] ") {
			return "n"
		}
		return ""
	}
	a, ctx := begin(t, t.Context(), b, true)
	_, err := dialVia(ctx, t, g, "alice:prod", client.Auth{}, key, a, true, nil)
	if !errors.Is(err, errNotReady) {
		t.Fatalf("declined host key must fail setup, got %v", err)
	}
}

func TestGatewaySetupNegative(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*standIn, *browser, *Attempt)
		want  error
	}{
		{"no marker", func(g *standIn, _ *browser, _ *Attempt) { g.noMarker = true }, errNotReady},
		{"exit status", func(g *standIn, _ *browser, _ *Attempt) { g.exitStatus = 3 }, errNotReady},
		{"browser stops acknowledging", func(g *standIn, b *browser, a *Attempt) {
			g.floodOutput = 64 << 10
			b.noAck = true
			a.ackTimeout = 200 * time.Millisecond
		}, ErrCancelled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, _ := newStandIn(t, "otp")
			b := newBrowser()
			b.answer = answerOTP(g.otp)
			a, ctx := begin(t, t.Context(), b, true)
			tc.setup(g, b, a)
			start := time.Now()
			if _, err := dialVia(ctx, t, g, "alice:prod", client.Auth{}, nil, a, true, nil); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if time.Since(start) > 5*time.Second {
				t.Fatalf("setup failure took %v", time.Since(start))
			}
		})
	}
}

func TestGatewayLargeOutputKeepsUTF8(t *testing.T) {
	g, _ := newStandIn(t, "otp")
	g.floodOutput = 256 << 10
	b := newBrowser()
	b.answer = answerOTP(g.otp)
	a, ctx := begin(t, t.Context(), b, true)
	if _, err := dialVia(ctx, t, g, "alice:prod", client.Auth{}, nil, a, true, nil); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(b.text(), '�') {
		t.Fatal("multi-byte characters split across frames were replaced")
	}
}

// TestAuthOrderAndFallbacks is the regression table of the method choice
// (K8 section 4.3); the Python differential in python_test.go runs the same
// scenarios through GatewayAuthStrategy.
func TestAuthOrderAndFallbacks(t *testing.T) {
	tests := []struct {
		name     string
		methods  string
		user     string
		password string // "" = none saved, "*" = the server's password
		otp      string // what the browser answers
		wantErr  error
		wantUsed []string
		wantAsk  int // prompts shown to the browser
	}{
		{"otp only, selector", "otp", "alice:prod", "", "424242", nil, []string{"keyboard-interactive"}, 1},
		{"saved password", "password", "alice:prod", "*", "", nil, []string{"password"}, 0},
		{"password asked in browser", "password", "alice:prod", "", "", nil, []string{"password"}, 1},
		{"password then otp", "password+otp", "alice:prod", "*", "424242", nil, []string{"password", "keyboard-interactive"}, 1},
		{"PAM: ki preferred over saved password", "ki+password", "pwuser", "*", "424242", nil, []string{"keyboard-interactive"}, 1},
		{"broken ki falls back to saved password", "ki-broken+password", "pwuser", "*", "", nil, []string{"keyboard-interactive", "password"}, 0},
		{"rejected otp never sends the password", "ki+password", "pwuser", "*", "000000", ErrFactorRejected, []string{"keyboard-interactive"}, 1},
		{"wrong saved password", "password", "alice:prod", "wrong", "", ErrAuthFailed, []string{"password"}, 0},
		{"wrong otp after password", "password+otp", "alice:prod", "*", "000000", ErrFactorRejected, []string{"password", "keyboard-interactive"}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, _ := newStandIn(t, tt.methods)
			b := newBrowser()
			b.answer = func(title string, p []Prompt) []string {
				if len(p) == 1 && p[0].Label == "Password" {
					return []string{g.password}
				}
				return answerOTP(tt.otp)(title, p)
			}
			var auth client.Auth
			switch tt.password {
			case "*":
				auth.Password = g.password
			case "":
			default:
				auth.Password = tt.password
			}
			a, ctx := begin(t, t.Context(), b, IsSelector(tt.user))
			_, err := dialVia(ctx, t, g, tt.user, auth, nil, a, false, nil)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr != nil && fault.CodeOf(err) != fault.AuthFailed {
				t.Fatalf("code %s", fault.CodeOf(err))
			}
			if got := g.used(); !slices.Equal(got, tt.wantUsed) {
				t.Fatalf("methods %v, want %v", got, tt.wantUsed)
			}
			if len(b.asked()) != tt.wantAsk {
				t.Fatalf("browser prompts %v", b.asked())
			}
		})
	}
}

func TestCancelDuringChallengeClosesConnection(t *testing.T) {
	g, _ := newStandIn(t, "otp")
	b := newBrowser() // never answers
	ctx, cancel := context.WithCancel(t.Context())
	a, actx := begin(t, ctx, b, true)
	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	_, err := dialVia(actx, t, g, "alice:prod", client.Auth{}, nil, a, true, nil)
	if c := fault.CodeOf(err); c != fault.Cancelled {
		t.Fatalf("got %v (%s)", err, c)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("cancel took %v", d)
	}
}

func TestSwitchOffEndsTheAttempt(t *testing.T) {
	g, _ := newStandIn(t, "otp")
	b := newBrowser() // never answers
	r := &Registry{}
	a, actx, end, err := r.Begin(t.Context(), b.owner, "req-1", b.ev, true)
	if err != nil {
		t.Fatal(err)
	}
	defer end()
	go b.run(actx, a)
	done := make(chan error, 1)
	go func() {
		_, err := dialVia(actx, t, g, "alice:prod", client.Auth{}, nil, a, true, nil)
		done <- err
	}()
	for len(b.challenges()) == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	r.Disable()
	select {
	case err := <-done:
		if c := fault.CodeOf(err); c != fault.Forbidden && c != fault.Cancelled {
			t.Fatalf("after switch-off: %v (%s)", err, c)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("switch-off did not end the attempt")
	}
	if !errors.Is(a.Check(), ErrDisabled) {
		t.Fatal("check does not report the switch")
	}
}

func TestSwitchReadOffStopsTheNextStep(t *testing.T) {
	g, _ := newStandIn(t, "password+otp")
	b := newBrowser()
	b.answer = answerOTP(g.otp)
	enabled := true
	now := time.Now()
	r := &Registry{Enabled: func(context.Context) bool { return enabled }, Now: func() time.Time { return now }}
	a, actx, end, err := r.Begin(t.Context(), b.owner, "req-1", b.ev, true)
	if err != nil {
		t.Fatal(err)
	}
	defer end()
	go b.run(actx, a)
	enabled = false
	now = now.Add(2 * recheckInterval)
	_, err = dialVia(actx, t, g, "alice:prod", client.Auth{Password: g.password}, nil, a, true, nil)
	if !errors.Is(err, ErrDisabled) || fault.CodeOf(err) != fault.Forbidden {
		t.Fatalf("switched off before the first method: %v", err)
	}
	if len(g.used()) != 0 {
		t.Fatalf("a method ran after the switch went off: %v", g.used())
	}
	if _, _, _, err := r.Begin(t.Context(), b.owner, "req-2", b.ev, true); !errors.Is(err, ErrDisabled) {
		t.Fatalf("begin while off: %v", err)
	}
	if _, _, end, err := r.Begin(t.Context(), b.owner, "req-3", b.ev, false); err != nil {
		t.Fatalf("an ordinary attempt does not need the switch: %v", err)
	} else {
		end()
	}
}

func TestQuickSFTPTwoChannels(t *testing.T) {
	g, _ := newStandIn(t, "otp")
	b := newBrowser()
	b.answer = answerOTP(g.otp)
	a, ctx := begin(t, t.Context(), b, true)
	var version byte
	_, err := dialVia(ctx, t, g, "alice:prod", client.Auth{}, nil, a, false, func(ctx context.Context, c *ssh.Client) error {
		var err error
		version, err = OpenWithPrompts(ctx, SSHSessions(c), a, func(ctx context.Context) (byte, error) {
			return sftpHandshake(ctx, c)
		})
		return err
	})
	if err != nil || version != 3 {
		t.Fatalf("sftp version %d, %v", version, err)
	}
}

func TestJumpHostPromptsCarryTheJumpHost(t *testing.T) {
	jump, _ := newStandIn(t, "otp")
	b := newBrowser()
	b.answer = answerOTP(jump.otp)
	a, ctx := begin(t, t.Context(), b, false)
	ask := hopChallenger{attempt: a, req: client.AuthRequest{Role: client.RoleJump, Host: "bastion.lan"}}
	got, err := ask.Challenge(ctx, "Warpgate", "Enter code", []Prompt{{Label: "OTP: "}})
	if err != nil || len(got) != 1 {
		t.Fatalf("challenge: %v %v", got, err)
	}
	shown := b.challenges()[0]
	if shown.Title != "Jump host: bastion.lan" || shown.Instructions != "Warpgate\nEnter code" || shown.Context != "jump_host" {
		t.Fatalf("jump challenge %+v", shown)
	}
}
