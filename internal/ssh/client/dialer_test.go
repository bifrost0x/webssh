package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/fault"
)

func TestPassword(t *testing.T) {
	calls := 0
	s := startServer(t, passwordServer("u", "pw", &calls))
	d, _ := newDialer(trusting(s), nil)
	c, err := d.Dial(t.Context(), target(s, "u", Auth{Password: "pw"}), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	_, err = d.Dial(t.Context(), target(s, "u", Auth{Password: "wrong"}), nil)
	if role, code := hopOf(t, err); role != RoleTarget || code != fault.AuthFailed {
		t.Fatalf("wrong password: %s %s", role, code)
	}
	if _, _, msg := fault.Status(err); strings.Contains(msg, "denied") {
		t.Fatalf("message leaks server text: %q", msg)
	}
	if calls != 2 {
		t.Fatalf("password sent %d times, want once per dial", calls)
	}
}

func kiServer(prompts []string, answers []string, password *int) *ssh.ServerConfig {
	return &ssh.ServerConfig{
		KeyboardInteractiveCallback: func(_ ssh.ConnMetadata, ask ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			for i, p := range prompts {
				got, err := ask("", "", []string{p}, []bool{false})
				if err != nil {
					return nil, err
				}
				if len(got) != 1 || got[0] != answers[i] {
					return nil, errors.New("wrong answer")
				}
			}
			return nil, nil
		},
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			if password != nil {
				*password++
			}
			return nil, errors.New("password method refused")
		},
	}
}

// The password answers the first hidden keyboard-interactive prompt when
// the server does not offer the password method.
func TestKeyboardInteractiveFallback(t *testing.T) {
	cfg := kiServer([]string{"Password: "}, []string{"pw"}, nil)
	cfg.PasswordCallback = nil
	s := startServer(t, cfg)
	d, _ := newDialer(trusting(s), nil)
	c, err := d.Dial(t.Context(), target(s, "u", Auth{Password: "pw"}), &prompts{})
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
}

// A second prompt (a one-time code) is not answered with anything: an
// attended connection ends with not_available_in_preview, an unattended
// one with interaction_required.
func TestSecondPromptNeedsTheUser(t *testing.T) {
	cfg := kiServer([]string{"Password: ", "Verification code: "}, []string{"pw", "123456"}, nil)
	cfg.PasswordCallback = nil
	s := startServer(t, cfg)
	d, _ := newDialer(trusting(s), nil)
	_, err := d.Dial(t.Context(), target(s, "u", Auth{Password: "pw"}), &prompts{})
	if _, code := hopOf(t, err); code != fault.NotAvailableInPreview {
		t.Fatalf("attended: %v", err)
	}
	_, err = d.Dial(t.Context(), target(s, "u", Auth{Password: "pw"}), nil)
	if _, code := hopOf(t, err); code != fault.InteractionRequired {
		t.Fatalf("unattended: %v", err)
	}
}

// After a failed password the same secret is not offered again through
// keyboard-interactive (paramiko fell back only when the password method
// was not allowed).
func TestNoKeyboardInteractiveAfterFailedPassword(t *testing.T) {
	kiCalls := 0
	cfg := kiServer([]string{"Password: "}, []string{"never"}, nil)
	ki := cfg.KeyboardInteractiveCallback
	cfg.KeyboardInteractiveCallback = func(c ssh.ConnMetadata, ask ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
		kiCalls++
		return ki(c, ask)
	}
	s := startServer(t, cfg)
	d, _ := newDialer(trusting(s), nil)
	_, err := d.Dial(t.Context(), target(s, "u", Auth{Password: "pw"}), &prompts{})
	if _, code := hopOf(t, err); code != fault.AuthFailed || kiCalls != 0 {
		t.Fatalf("got %v after %d keyboard-interactive attempts", err, kiCalls)
	}
}

// K8: after an answered prompt the password is never sent, even when the
// server then lists the password method (Warpgate drops
// keyboard-interactive after a rejected answer). Same for a rejected
// answer followed by keyboard-interactive again (M7).
func TestNoMethodAfterAnsweredPrompt(t *testing.T) {
	plan := &authPlan{ctx: t.Context(), password: "pw", attended: true, answered: true}
	for _, c := range []*ssh.ClientAuthContext{
		{AllowedMethods: []string{"password"}, TriedMethods: []string{"none", "keyboard-interactive"}},
		{AllowedMethods: []string{"keyboard-interactive", "password"}, TriedMethods: []string{"none", "keyboard-interactive"}},
	} {
		if m, err := plan.next(c); m != nil || !errors.Is(err, errAuthExhausted) {
			t.Errorf("%+v: method %v, err %v", c, m, err)
		}
	}
	// The same server shape end to end: keyboard-interactive only, the
	// answer is rejected, the password callback is never reached.
	passwordCalls := 0
	cfg := kiServer([]string{"Password: "}, []string{"other"}, &passwordCalls)
	cfg.PasswordCallback = nil
	s := startServer(t, cfg)
	d, _ := newDialer(trusting(s), nil)
	_, err := d.Dial(t.Context(), target(s, "u", Auth{Password: "pw"}), &prompts{})
	if _, code := hopOf(t, err); code != fault.AuthFailed || passwordCalls != 0 {
		t.Fatalf("got %v, %d password attempts", err, passwordCalls)
	}
}

func TestPromptRoundsAreBounded(t *testing.T) {
	rounds := 0
	s := startServer(t, &ssh.ServerConfig{
		KeyboardInteractiveCallback: func(_ ssh.ConnMetadata, ask ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			for {
				rounds++
				if _, err := ask("", "", nil, nil); err != nil {
					return nil, err
				}
			}
		},
	})
	d, _ := newDialer(trusting(s), nil)
	_, err := d.Dial(t.Context(), target(s, "u", Auth{Password: "pw"}), &prompts{})
	if _, code := hopOf(t, err); code != fault.AuthFailed || rounds != maxPromptRounds+1 {
		t.Fatalf("got %v after %d rounds", err, rounds)
	}
}

func clientKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func TestPublicKeyThenPassword(t *testing.T) {
	key := clientKey(t)
	s := startServer(t, &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if string(k.Marshal()) != string(key.PublicKey().Marshal()) {
				return nil, errors.New("unknown key")
			}
			return nil, &ssh.PartialSuccessError{Next: ssh.ServerAuthCallbacks{
				PasswordCallback: func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
					if string(pw) == "pw" {
						return nil, nil
					}
					return nil, errors.New("no")
				},
			}}
		},
	})
	d, _ := newDialer(trusting(s), keyMap{"k1": key})
	c, err := d.Dial(t.Context(), target(s, "u", Auth{KeyID: "k1", Password: "pw"}), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	// Key only: the second factor needs the user.
	_, err = d.Dial(t.Context(), target(s, "u", Auth{KeyID: "k1"}), &prompts{})
	if _, code := hopOf(t, err); code != fault.NotAvailableInPreview {
		t.Fatalf("key only: %v", err)
	}
	_, err = d.Dial(t.Context(), target(s, "u", Auth{KeyID: "missing"}), nil)
	if _, code := hopOf(t, err); code != fault.NotFound {
		t.Fatalf("missing key: %v", err)
	}
}

// M4: without an Interaction an unknown host key is refused and nothing
// is recorded (no silent trust on first use).
func TestUnknownHostKeyUnattended(t *testing.T) {
	calls := 0
	s := startServer(t, passwordServer("u", "pw", &calls))
	hk := trusting()
	d, _ := newDialer(hk, nil)
	_, err := d.Dial(t.Context(), target(s, "u", Auth{Password: "pw"}), nil)
	if _, code := hopOf(t, err); code != fault.HostKeyNotAccepted || hk.recorded != 0 || calls != 0 {
		t.Fatalf("got %v, %d recorded, %d password attempts", err, hk.recorded, calls)
	}
}

func TestHostKeyPrompt(t *testing.T) {
	calls := 0
	s := startServer(t, passwordServer("u", "pw", &calls))
	tgt := target(s, "u", Auth{Password: "pw"})

	hk := trusting()
	d, _ := newDialer(hk, nil)
	for name, ix := range map[string]*prompts{"declined": {}, "failed": {accept: true, err: errors.New("ui gone")}} {
		_, err := d.Dial(t.Context(), tgt, ix)
		if _, code := hopOf(t, err); code != fault.HostKeyNotAccepted || hk.recorded != 0 || len(ix.hostKeys) != 1 {
			t.Fatalf("%s: %v, %d recorded", name, err, hk.recorded)
		}
	}

	ix := &prompts{accept: true}
	c, err := d.Dial(t.Context(), tgt, ix)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	q := ix.hostKeys[0]
	if hk.recorded != 1 || q.Role != RoleTarget || q.Host != "127.0.0.1" || q.Port != s.port || q.KeyType != ssh.KeyAlgoED25519 || q.Fingerprint != ssh.FingerprintSHA256(s.hostKey) {
		t.Fatalf("prompt %+v, %d recorded", q, hk.recorded)
	}
	// Known now: no second prompt.
	c, err = d.Dial(t.Context(), tgt, ix)
	if err != nil || len(ix.hostKeys) != 1 {
		t.Fatalf("second dial: %v, %d prompts", err, len(ix.hostKeys))
	}
	_ = c.Close()

	// A changed key is refused without a prompt.
	hk.keys[joinHostPort(s.host, s.port)] = clientKey(t).PublicKey()
	if _, err := d.Dial(t.Context(), tgt, ix); fault.CodeOf(err) != fault.HostKeyChanged || len(ix.hostKeys) != 1 {
		t.Fatalf("changed: %v", err)
	}
	// Another session recorded a different key meanwhile.
	race := trusting()
	race.recordErr = fault.New(fault.HostKeyChanged, "")
	d, _ = newDialer(race, nil)
	if _, err := d.Dial(t.Context(), tgt, &prompts{accept: true}); fault.CodeOf(err) != fault.HostKeyChanged {
		t.Fatalf("record race: %v", err)
	}
	// A store that cannot be read refuses the connection.
	broken := trusting()
	broken.knownErr = fault.New(fault.StorageError, "line 2")
	d, _ = newDialer(broken, nil)
	if _, err := d.Dial(t.Context(), tgt, &prompts{accept: true}); fault.CodeOf(err) != fault.StorageError {
		t.Fatalf("broken store: %v", err)
	}
}

// Cancelling while the user is asked ends the attempt at once; the time
// the prompt is open does not count against the handshake budget.
func TestCancelDuringPrompt(t *testing.T) {
	calls := 0
	s := startServer(t, passwordServer("u", "pw", &calls))
	d, _ := newDialer(trusting(), nil)
	d.HandshakeTimeout = 200 * time.Millisecond
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(600*time.Millisecond, cancel)
	start := time.Now()
	_, err := d.Dial(ctx, target(s, "u", Auth{Password: "pw"}), &prompts{block: true})
	if _, code := hopOf(t, err); code != fault.Cancelled {
		t.Fatalf("got %v", err)
	}
	if took := time.Since(start); took < 500*time.Millisecond || took > 3*time.Second {
		t.Fatalf("took %v", took)
	}
}

func bannerServer(banner string) *ssh.ServerConfig {
	calls := 0
	cfg := passwordServer("u", "pw", &calls)
	cfg.BannerCallback = func(ssh.ConnMetadata) string { return banner }
	return cfg
}

func TestBanner(t *testing.T) {
	s := startServer(t, bannerServer("  Authorized use only.\r\nLine 2\x1b[31m\x07\u200b\tend  \n"))
	d, _ := newDialer(trusting(s), nil)
	ix := &prompts{banner: true}
	c, err := d.Dial(t.Context(), target(s, "u", Auth{Password: "pw"}), ix)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if len(ix.banners) != 1 || ix.banners[0].Banner != "Authorized use only.\nLine 2[31m\tend" || ix.banners[0].Role != RoleTarget {
		t.Fatalf("banner %+v", ix.banners)
	}
	for name, ix := range map[string]Interaction{"declined": &prompts{}, "unattended": nil} {
		if _, err := d.Dial(t.Context(), target(s, "u", Auth{Password: "pw"}), ix); fault.CodeOf(err) != fault.BannerDeclined {
			t.Errorf("%s: %v", name, err)
		}
	}
	if got := sanitizeBanner(strings.Repeat("x", 2*maxBannerChars)); len(got) != maxBannerChars {
		t.Fatalf("banner not bounded: %d", len(got))
	}
}

func TestJumpChain(t *testing.T) {
	calls := 0
	inner := startServer(t, passwordServer("in", "pw2", &calls))
	middle := startServer(t, passwordServer("mid", "pw1", &calls))
	outer := startServer(t, passwordServer("out", "pw0", &calls))
	d, n := newDialer(trusting(), nil)
	ix := &prompts{accept: true}
	tgt := Target{Owner: 1,
		Jumps: []Hop{
			{Host: outer.host, Port: outer.port, User: "out", Auth: Auth{Password: "pw0"}},
			{Host: middle.host, Port: middle.port, User: "mid", Auth: Auth{Password: "pw1"}},
		},
		Hop: Hop{Host: inner.host, Port: inner.port, User: "in", Auth: Auth{Password: "pw2"}},
	}
	c, err := d.Dial(t.Context(), tgt, ix)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if len(ix.hostKeys) != 3 || ix.hostKeys[0].Role != RoleJump || ix.hostKeys[2].Role != RoleTarget {
		t.Fatalf("prompts %+v", ix.hostKeys)
	}
	if len(n.dials) != 1 || !strings.HasPrefix(n.dials[0], "ssh-relay ") {
		t.Fatalf("the first jump host must be dialled as a relay: %v", n.dials)
	}
	if len(outer.forward) != 1 || len(middle.forward) != 1 {
		t.Fatalf("forwarded %v %v", outer.forward, middle.forward)
	}
	// A wrong password on the jump host names the jump host.
	tgt.Jumps[1].Auth.Password = "wrong"
	_, err = d.Dial(t.Context(), tgt, ix)
	if role, code := hopOf(t, err); role != RoleJump || code != fault.AuthFailed {
		t.Fatalf("jump failure: %s %s", role, code)
	}
	// The target behind the jump host is not reachable.
	tgt.Jumps = tgt.Jumps[:1]
	tgt.Hop.Port = 1
	_, err = d.Dial(t.Context(), tgt, ix)
	if role, code := hopOf(t, err); role != RoleTarget || code != fault.ChannelRejected {
		t.Fatalf("unreachable target: %s %s (%v)", role, code, err)
	}
}

func TestValidate(t *testing.T) {
	d, n := newDialer(trusting(), nil)
	hop := Hop{Host: "h.test", Port: 22, User: "u", Auth: Auth{Password: "x"}}
	for name, tgt := range map[string]Target{
		"no owner":       {Hop: hop},
		"jump and proxy": {Owner: 1, Hop: hop, Jumps: []Hop{hop}, Proxy: &SOCKS{Host: "p", Port: 1080}},
		"too many jumps": {Owner: 1, Hop: hop, Jumps: []Hop{hop, hop, hop, hop, hop}},
		"no user":        {Owner: 1, Hop: Hop{Host: "h", Port: 22, Auth: Auth{Password: "x"}}},
		"bad port":       {Owner: 1, Hop: Hop{Host: "h", Port: 0, User: "u", Auth: Auth{Password: "x"}}},
		"no auth":        {Owner: 1, Hop: Hop{Host: "h", Port: 22, User: "u"}},
		"bad host":       {Owner: 1, Hop: Hop{Host: "bad_host", Port: 22, User: "u", Auth: Auth{Password: "x"}}},
		"no key source":  {Owner: 1, Hop: Hop{Host: "h", Port: 22, User: "u", Auth: Auth{KeyID: "k"}}},
	} {
		if _, err := d.Dial(t.Context(), tgt, nil); err == nil || fault.CodeOf(err) == fault.Internal {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := (&Dialer{}).Dial(t.Context(), Target{Owner: 1, Hop: hop}, nil); fault.CodeOf(err) != fault.InvalidRequest {
		t.Errorf("unconfigured dialer: %v", err)
	}
	if len(n.dials) != 0 {
		t.Fatalf("dialled %v", n.dials)
	}
}

func TestShell(t *testing.T) {
	calls := 0
	s := startServer(t, passwordServer("u", "pw", &calls))
	d, _ := newDialer(trusting(s), nil)
	sh, err := d.OpenShell(t.Context(), target(s, "u", Auth{Password: "pw"}), nil, 24, 80)
	if err != nil {
		t.Fatal(err)
	}
	if err := sh.Resize(43, 132); err != nil {
		t.Fatal(err)
	}
	if err := sh.Resize(0, 80); err == nil {
		t.Fatal("zero rows accepted")
	}
	if _, err := io.WriteString(sh, "hello\nexit\n"); err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(sh)
	if !strings.Contains(string(out), "hello") {
		t.Fatalf("output %q", out)
	}
	if err := sh.Wait(); err != nil {
		t.Fatalf("wait: %v", err)
	}
	if err := sh.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.resizes) != 1 || s.resizes[0] != [2]uint32{132, 43} {
		t.Fatalf("window changes %v", s.resizes)
	}
	if _, err := d.OpenShell(t.Context(), target(s, "u", Auth{Password: "pw"}), nil, 0, 0); fault.CodeOf(err) != fault.InvalidValue {
		t.Fatalf("bad size: %v", err)
	}
}

func TestKeepaliveClosesDeadPeer(t *testing.T) {
	calls := 0
	s := startServer(t, passwordServer("u", "pw", &calls))
	d, _ := newDialer(trusting(s), nil)
	d.Keepalive = 50 * time.Millisecond
	c, err := d.Dial(t.Context(), target(s, "u", Auth{Password: "pw"}), nil)
	if err != nil {
		t.Fatal(err)
	}
	// The server answers keepalives, so the connection stays up.
	time.Sleep(200 * time.Millisecond)
	select {
	case <-c.Done():
		t.Fatal("closed although the peer answers")
	default:
	}
	close(s.silent)
	select {
	case <-c.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("a peer that stopped answering keeps the connection")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("close after keepalive failure: %v", err)
	}
}

// A server that accepts TCP and never speaks SSH runs into the handshake
// budget.
func TestHandshakeTimeout(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	d, _ := newDialer(trusting(), nil)
	d.HandshakeTimeout = 300 * time.Millisecond
	port := l.Addr().(*net.TCPAddr).Port
	start := time.Now()
	_, err = d.Dial(t.Context(), Target{Owner: 1, Hop: Hop{Host: "127.0.0.1", Port: port, User: "u", Auth: Auth{Password: "x"}}}, nil)
	if _, code := hopOf(t, err); code != fault.Timeout {
		t.Fatalf("got %v", err)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("took %v", took)
	}
}
