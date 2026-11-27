//go:build lab

// The lab tests run the gateway variant of the shared dialer against
// OpenSSH with PAM and TOTP in the test lab (tests/lab). Run them with
//
//	go test -tags lab -run Lab ./internal/ssh/gateway
//
// They fail, not skip, when the lab is not reachable. The lab's TOTP module
// allows ten logins per 30 s and account, shared with other lab tests, so
// these tests log in with a code at most once each.
package gateway

import (
	"bytes"
	"context"
	json "encoding/json/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/otp"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

type labService struct {
	Host         string            `json:"host"`
	Port         int               `json:"port"`
	InternalHost string            `json:"internal_host"`
	InternalPort int               `json:"internal_port"`
	Fingerprints map[string]string `json:"host_key_fingerprints"`
}

type labFile struct {
	dir      string
	Services map[string]labService `json:"services"`
}

func lab(t *testing.T) labFile {
	t.Helper()
	path := os.Getenv("WEBSSH_LAB_JSON")
	if path == "" {
		path = filepath.Join("..", "..", "..", "tests", "lab", "runtime", "lab.json")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("lab not available (set WEBSSH_LAB_JSON): %v", err)
	}
	l := labFile{dir: filepath.Dir(path)}
	if err := json.Unmarshal(raw, &l); err != nil {
		t.Fatal(err)
	}
	return l
}

func (l labFile) secret(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(l.dir, "secrets", name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func (l labFile) code(t *testing.T, name string) string {
	t.Helper()
	key, err := otp.DecodeSecret(l.secret(t, name))
	if err != nil {
		t.Fatal(err)
	}
	code, err := otp.TOTP(key, otp.Step(time.Now(), 30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func (l labFile) signer(t *testing.T) ssh.Signer {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(l.dir, "ssh", "client", "ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.ParsePrivateKey(b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// labKeys trusts the fingerprints the lab published for every service.
type labKeys struct{ l labFile }

func (k labKeys) Known(_ context.Context, _ int64, _ string, _ int, key ssh.PublicKey) (bool, error) {
	fp := ssh.FingerprintSHA256(key)
	for _, svc := range k.l.Services {
		for _, want := range svc.Fingerprints {
			if fp == want {
				return true, nil
			}
		}
	}
	return false, fault.New(fault.HostKeyChanged, "")
}

func (labKeys) Record(context.Context, int64, string, int, ssh.PublicKey) error { return nil }

func (labKeys) Preferred(_ context.Context, _ int64, _ string, _ int, allowed []string) ([]string, error) {
	return allowed, nil
}

// pamBrowser answers PAM's "Password: " and "Verification code: ".
func pamBrowser(password, code string) *browser {
	b := newBrowser()
	b.answer = func(_ string, prompts []Prompt) []string {
		out := make([]string, len(prompts))
		for i, p := range prompts {
			switch {
			case strings.HasPrefix(p.Label, "Password"):
				out[i] = password
			case strings.Contains(p.Label, "code"):
				out[i] = code
			}
		}
		return out
	}
	return b
}

func labDial(ctx context.Context, t *testing.T, l labFile, target client.Target, b *browser) (*client.Conn, error) {
	t.Helper()
	a, actx := begin(t, ctx, b, false)
	target.Owner, target.Variant = 7, a.Variant(false)
	d := &client.Dialer{Net: openNet{}, HostKeys: labKeys{l}, Keys: keySource{"k1": l.signer(t)}, Keepalive: -1}
	c, err := d.Dial(actx, target, nil)
	if c != nil {
		t.Cleanup(func() { _ = c.Close() })
	}
	return c, err
}

func labRun(ctx context.Context, t *testing.T, c *client.Conn, command string) string {
	t.Helper()
	var out bytes.Buffer
	status, err := c.Exec(ctx, command, nil, &out, nil)
	if err != nil || status != 0 {
		t.Fatalf("%s: %d %v", command, status, err)
	}
	return strings.TrimSpace(out.String())
}

// A key, then password and code in keyboard-interactive (partial success
// of OpenSSH), all prompts in the browser.
func TestLabMFAKeyThenPasswordAndTOTP(t *testing.T) {
	l := lab(t)
	svc := l.Services["ssh-modern"]
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	b := pamBrowser(l.secret(t, "ssh-mfauser"), l.code(t, "ssh-mfauser-totp-base32"))
	c, err := labDial(ctx, t, l, client.Target{Hop: client.Hop{Host: svc.Host, Port: svc.Port, User: "mfauser",
		Auth: client.Auth{KeyID: "k1"}}}, b)
	if err != nil {
		t.Fatalf("dial: %v (prompts %v)", err, b.asked())
	}
	var labels []string
	for _, p := range b.asked() {
		for _, q := range p {
			labels = append(labels, q.Label)
		}
	}
	if !slices.Contains(labels, "Password: ") || !slices.Contains(labels, "Verification code: ") {
		t.Fatalf("prompts %v", b.asked())
	}
	if got := labRun(ctx, t, c, "id -un"); got != "mfauser" {
		t.Fatalf("id -un = %q", got)
	}
}

// A jump host with a key in front of a target that asks password and
// code: the variant runs on both hops, the prompts come from the target.
func TestLabJumpHostThenInteractiveTarget(t *testing.T) {
	l := lab(t)
	bastion, inner := l.Services["ssh-bastion"], l.Services["ssh-inner"]
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	b := pamBrowser(l.secret(t, "ssh-kiuser"), l.code(t, "ssh-kiuser-totp-base32"))
	c, err := labDial(ctx, t, l, client.Target{
		Hop:   client.Hop{Host: inner.InternalHost, Port: inner.InternalPort, User: "kiuser", Auth: client.Auth{Password: l.secret(t, "ssh-kiuser")}},
		Jumps: []client.Hop{{Host: bastion.Host, Port: bastion.Port, User: "keyuser", Auth: client.Auth{KeyID: "k1"}}},
	}, b)
	if err != nil {
		t.Fatalf("dial: %v (prompts %+v)", err, b.challenges())
	}
	for _, c := range b.challenges() {
		if c.Context != "target" {
			t.Fatalf("challenge from %s: %+v", c.Context, c)
		}
	}
	if len(b.challenges()) == 0 {
		t.Fatal("the target asked nothing")
	}
	if got := labRun(ctx, t, c, "id -un"); got != "kiuser" {
		t.Fatalf("id -un = %q", got)
	}
}

// A saved password and a server that offers only the password method: no
// prompt reaches the browser.
func TestLabSavedPasswordWithoutPrompt(t *testing.T) {
	l := lab(t)
	svc := l.Services["ssh-modern"]
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	b := newBrowser()
	c, err := labDial(ctx, t, l, client.Target{Hop: client.Hop{Host: svc.Host, Port: svc.Port, User: "pwuser",
		Auth: client.Auth{Password: l.secret(t, "ssh-pwuser")}}}, b)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.asked()) != 0 {
		t.Fatalf("prompts %v", b.asked())
	}
	if got := labRun(ctx, t, c, "id -un"); got != "pwuser" {
		t.Fatalf("id -un = %q", got)
	}
}

// A saved password whose guard refuses is not sent to the lab server
// through the gateway strategy; the attempt ends with the guard's code.
func TestLabSavedPasswordGuardRefuses(t *testing.T) {
	l := lab(t)
	svc := l.Services["ssh-modern"]
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	guard := refusing()
	_, err := labDial(ctx, t, l, client.Target{Hop: client.Hop{Host: svc.Host, Port: svc.Port, User: "pwuser",
		Auth: client.Auth{Password: l.secret(t, "ssh-pwuser"), Guard: guard}}}, newBrowser())
	if fault.CodeOf(err) != fault.CredentialTargetChanged || guard.calls.Load() != 1 {
		t.Fatalf("err %v, guard calls %d", err, guard.calls.Load())
	}
}
