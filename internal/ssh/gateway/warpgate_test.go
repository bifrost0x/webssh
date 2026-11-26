//go:build warpgate

// The Warpgate tests run the gateway variant of the shared dialer against
// a real Warpgate in front of the test lab (testdata/warpgate-up.sh starts
// a throwaway one). Run them with
//
//	WEBSSH_WARPGATE_DIR=/tmp/webssh-warpgate WEBSSH_LAB_JSON=…/tests/lab/runtime/lab.json \
//	    go test -tags warpgate -run Warpgate -v ./internal/ssh/gateway
//
// They fail, not skip, when Warpgate or the lab is missing: a run that
// tested nothing must not look green. Warpgate blocks an address after five
// failed logins, so wrong codes are answered at most once per run.
package gateway

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/otp"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

type warpgate struct{ dir, lab string }

func loadWarpgate(t *testing.T) *warpgate {
	t.Helper()
	dir := os.Getenv("WEBSSH_WARPGATE_DIR")
	if dir == "" {
		t.Fatal("set WEBSSH_WARPGATE_DIR (testdata/warpgate-up.sh)")
	}
	labJSON := os.Getenv("WEBSSH_LAB_JSON")
	if labJSON == "" {
		labJSON = filepath.Join("..", "..", "..", "tests", "lab", "runtime", "lab.json")
	}
	if _, err := os.Stat(labJSON); err != nil {
		t.Fatalf("lab not available (set WEBSSH_LAB_JSON): %v", err)
	}
	return &warpgate{dir: dir, lab: filepath.Dir(labJSON)}
}

func (w *warpgate) read(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(w.dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func (w *warpgate) code(t *testing.T) string {
	t.Helper()
	key, err := hex.DecodeString(w.read(t, "otp.hex"))
	if err != nil {
		t.Fatal(err)
	}
	code, err := otp.TOTP(key, otp.Step(time.Now(), 30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func (w *warpgate) signer(t *testing.T) ssh.Signer {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(w.lab, "ssh", "client", "ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.ParsePrivateKey(b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// tofu is a host-key store whose first prompt the user accepts, as a user
// trusting the gateway's key in the browser would.
type tofu struct {
	mu    sync.Mutex
	keys  map[string][]byte
	asked int
}

func (s *tofu) Known(_ context.Context, _ int64, host string, _ int, key ssh.PublicKey) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[host]
	if !ok {
		return false, nil
	}
	if !bytes.Equal(k, key.Marshal()) {
		return false, fault.New(fault.HostKeyChanged, "")
	}
	return true, nil
}

func (s *tofu) Record(_ context.Context, _ int64, host string, _ int, key ssh.PublicKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keys == nil {
		s.keys = map[string][]byte{}
	}
	s.keys[host] = key.Marshal()
	return nil
}

func (*tofu) Preferred(_ context.Context, _ int64, _ string, _ int, allowed []string) ([]string, error) {
	return allowed, nil
}

func (s *tofu) HostKey(context.Context, client.HostKeyPrompt) (bool, error) {
	s.mu.Lock()
	s.asked++
	s.mu.Unlock()
	return true, nil
}

func (*tofu) Banner(context.Context, client.BannerPrompt) (bool, error) { return true, nil }

var trustPrompt = regexp.MustCompile(`(?i)(trust|accept|continue).*\?`)

// warpgateBrowser answers password and code prompts and the in-band
// host-key question of Warpgate.
func warpgateBrowser(t *testing.T, code, password string) *browser {
	b := newBrowser()
	b.answer = func(_ string, prompts []Prompt) []string {
		out := make([]string, len(prompts))
		for i, p := range prompts {
			if strings.HasPrefix(strings.ToLower(p.Label), "password") {
				out[i] = password
			} else {
				out[i] = code
			}
		}
		return out
	}
	typed := false
	b.onText = func(text string) string {
		if !typed && trustPrompt.MatchString(text) {
			typed = true
			t.Logf("gateway asked in-band: %q", lastLines(text, 3))
			return "y"
		}
		return ""
	}
	return b
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.Join(lines[max(0, len(lines)-n):], "\n")
}

func (w *warpgate) dial(ctx context.Context, t *testing.T, user string, auth client.Auth, signer ssh.Signer, b *browser,
	terminal bool, after func(context.Context, *ssh.Client) error) (*client.Conn, *tofu, error) {
	t.Helper()
	a, actx := begin(t, ctx, b, true)
	keys := keySource{}
	if signer != nil {
		auth.KeyID = "k1"
		keys["k1"] = signer
	}
	v := a.Variant(terminal)
	if after != nil {
		v.Ready = after
	}
	trust := &tofu{}
	d := &client.Dialer{Net: openNet{}, HostKeys: trust, Keys: keys}
	c, err := d.Dial(actx, client.Target{Owner: 7, Hop: client.Hop{Host: "127.0.0.1", Port: 12222, User: user, Auth: auth}, Variant: v}, trust)
	if c != nil {
		t.Cleanup(func() { _ = c.Close() })
	}
	return c, trust, err
}

func TestWarpgateKeyAndTOTPTerminal(t *testing.T) {
	w := loadWarpgate(t)
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	b := warpgateBrowser(t, w.code(t), "")
	c, trust, err := w.dial(ctx, t, "alice:modern", client.Auth{}, w.signer(t), b, true, nil)
	if err != nil {
		t.Fatalf("dial: %v (prompts %+v, output %q)", err, b.challenges(), lastLines(b.text(), 4))
	}
	t.Logf("prompts: %+v", b.challenges())
	t.Logf("setup output: %q", lastLines(b.text(), 4))
	if trust.asked != 1 {
		t.Fatalf("gateway host key asked %d times", trust.asked)
	}
	var out bytes.Buffer
	status, err := c.Exec(ctx, "id -un", nil, &out, nil)
	if err != nil || status != 0 || strings.TrimSpace(out.String()) != "pwuser" {
		t.Fatalf("command through Warpgate: %q %d %v", out.String(), status, err)
	}
}

func TestWarpgatePasswordAndTOTPQuickSFTP(t *testing.T) {
	w := loadWarpgate(t)
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	b := warpgateBrowser(t, w.code(t), "")
	var version byte
	_, _, err := w.dial(ctx, t, "bob:modern", client.Auth{Password: w.read(t, "bob.password")}, nil, b, false,
		func(ctx context.Context, c *ssh.Client) error {
			a := b.attempt
			var err error
			version, err = OpenWithPrompts(ctx, SSHSessions(c), a, func(ctx context.Context) (byte, error) { return sftpHandshake(ctx, c) })
			return err
		})
	if err != nil || version != 3 {
		t.Fatalf("Quick SFTP through Warpgate: %d %v; prompts %+v output %q", version, err, b.challenges(), lastLines(b.text(), 4))
	}
	t.Logf("prompts: %+v", b.challenges())
}

// Without a saved password the strategy starts with keyboard-interactive,
// as the Python release does. Warpgate asks the one-time code there and,
// after accepting it, drops keyboard-interactive from the list without the
// partial-success flag. After answered prompts that counts as a refusal,
// so the attempt ends before any password is asked or sent: the same
// outcome as GatewayAuthStrategy (kept; a saved password works, see
// TestWarpgatePasswordAndTOTPQuickSFTP).
func TestWarpgateWithoutSavedPasswordEndsAsInPython(t *testing.T) {
	w := loadWarpgate(t)
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	b := warpgateBrowser(t, w.code(t), w.read(t, "bob.password"))
	_, _, err := w.dial(ctx, t, "bob:modern", client.Auth{}, nil, b, true, nil)
	if !errors.Is(err, ErrFactorRejected) {
		t.Fatalf("dial: %v (prompts %+v)", err, b.challenges())
	}
	for _, c := range b.challenges() {
		for _, p := range c.Prompts {
			if p.Label == "Password" {
				t.Fatalf("password asked after the code: %+v", b.challenges())
			}
		}
	}
	t.Logf("prompts: %+v", b.challenges())
}

// Warpgate asks again after a wrong code within the same exchange; WebSSH
// shows each round. The browser answers wrong once, then gives up, and the
// saved password is never sent a second time.
func TestWarpgateWrongTOTP(t *testing.T) {
	w := loadWarpgate(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	b := newBrowser()
	rounds := 0
	b.answer = func(string, []Prompt) []string {
		rounds++
		if rounds == 1 {
			return []string{"000000"}
		}
		cancel()
		return nil
	}
	_, _, err := w.dial(ctx, t, "bob:modern", client.Auth{Password: w.read(t, "bob.password")}, nil, b, true, nil)
	if err == nil {
		t.Fatal("wrong code accepted")
	}
	if rounds != 2 {
		t.Fatalf("expected a second prompt after the wrong code, got %d rounds", rounds)
	}
	if c := fault.CodeOf(err); c != fault.Cancelled {
		t.Fatalf("giving up: %v (%s)", err, c)
	}
}

func TestWarpgateUnknownTarget(t *testing.T) {
	w := loadWarpgate(t)
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	b := warpgateBrowser(t, w.code(t), "")
	_, _, err := w.dial(ctx, t, "bob:nosuchtarget", client.Auth{Password: w.read(t, "bob.password")}, nil, b, true, nil)
	if err == nil {
		t.Fatal("unknown target connected")
	}
	t.Logf("refused: %v (%s); output %q", err, fault.CodeOf(err), lastLines(b.text(), 3))
}
