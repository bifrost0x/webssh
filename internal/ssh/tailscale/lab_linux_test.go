//go:build linux

package tailscale

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/netpolicy"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// These tests run inside lab-ts-node, the Tailscale stand-in of the test
// lab, as an unprivileged user without capabilities
// (internal/netpolicy/testdata/netns-test.sh lab). They use the real
// kernel route lookup, the real interface binding and the shared dialer.
// The stand-in is no tailscaled: see the residual risk in the package
// documentation of the report.

type fingerprintKeys []string

func (f fingerprintKeys) Known(_ context.Context, _ int64, _ string, _ int, key ssh.PublicKey) (bool, error) {
	if slices.Contains(f, ssh.FingerprintSHA256(key)) {
		return true, nil
	}
	return false, fault.New(fault.HostKeyChanged, "")
}
func (fingerprintKeys) Record(context.Context, int64, string, int, ssh.PublicKey) error { return nil }
func (fingerprintKeys) Preferred(_ context.Context, _ int64, _ string, _ int, a []string) ([]string, error) {
	return a, nil
}

func labNamespace(t *testing.T) {
	t.Helper()
	if os.Getenv("WEBSSH_NETNS") != "lab" {
		t.Skip("run with internal/netpolicy/testdata/netns-test.sh lab")
	}
}

func labPolicy() *Policy {
	return New(Config{
		Enabled: true, Interface: "tailscale0", AllowedWebSSHUsers: []string{"operator"},
		AllowedTargets:     []Target{{"100.100.100.10", 22}, {"100.100.100.2", 22}, {"ts-target.lab", 22}, {"::ffff:100.100.100.10", 22}},
		AllowedRemoteUsers: []string{"tsuser"},
	}, func(_ context.Context, host string) ([]netip.Addr, error) {
		if host == "ts-target.lab" {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		}
		return nil, errors.New("no such name")
	}, nil)
}

func TestLabSharedIdentityEndToEnd(t *testing.T) {
	labNamespace(t)
	fingerprints := fingerprintKeys(strings.Split(os.Getenv("WEBSSH_TS_FINGERPRINTS"), ","))
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	p, operator := labPolicy(), User{ID: 2, Username: "operator"}
	auth, err := p.Authorize(ctx, operator, "100.100.100.10", 22, "tsuser")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	t.Logf("authorized %v via %s", auth.Addr(), auth.Interface())
	d := &client.Dialer{Net: refusingNet{t}, HostKeys: fingerprints, Keepalive: -1}
	c, err := d.Dial(ctx, client.Target{Owner: 2, Hop: client.Hop{Host: "100.100.100.10", Port: 22, User: "tsuser"},
		Display: client.Display{Tailscale: true}, Variant: auth.Variant()}, nil)
	if err != nil {
		t.Fatalf("none through the pinned socket: %v", err)
	}
	defer func() { _ = c.Close() }()
	var out bytes.Buffer
	if status, err := c.Exec(ctx, "id -un", nil, &out, nil); err != nil || status != 0 || strings.TrimSpace(out.String()) != "tsuser" {
		t.Fatalf("command as tsuser: %q %d %v", out.String(), status, err)
	}

	for name, tc := range map[string]struct {
		user User
		host string
	}{
		"own tailnet address (local route)": {operator, "100.100.100.2"},
		"name outside the tailnet":          {operator, "ts-target.lab"},
		"IPv4-mapped literal":               {operator, "::ffff:100.100.100.10"},
		"unlisted WebSSH user":              {User{ID: 3, Username: "guest"}, "100.100.100.10"},
	} {
		if _, err := p.Authorize(ctx, tc.user, tc.host, 22, "tsuser"); err == nil {
			t.Errorf("%s authorized", name)
		}
	}
}

// TestLabInterfacePinning shows that the bound socket cannot leave through
// another interface: ssh-modern answers on eth0 without binding and is out
// of reach bound to tailscale0, while the tailnet target answers.
func TestLabInterfacePinning(t *testing.T) {
	labNamespace(t)
	lan, err := netip.ParseAddrPort(os.Getenv("WEBSSH_LAB_SSH_MODERN"))
	if err != nil {
		t.Fatalf("WEBSSH_LAB_SSH_MODERN: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	banner := func(c net.Conn) string {
		defer func() { _ = c.Close() }()
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 64)
		n, _ := c.Read(buf)
		return string(buf[:n])
	}
	var d net.Dialer
	plain, err := d.DialContext(ctx, "tcp4", lan.String())
	if err != nil {
		t.Fatalf("ssh-modern without binding: %v", err)
	}
	if !strings.HasPrefix(banner(plain), "SSH-2.0-") {
		t.Fatal("ssh-modern sent no banner")
	}
	short, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	if c, err := netpolicy.DialInterface(short, "tailscale0", lan); err == nil {
		_ = c.Close()
		t.Fatal("bound to tailscale0, ssh-modern on eth0 was reached")
	}
	ts, err := netpolicy.DialInterface(ctx, "tailscale0", netip.MustParseAddrPort("100.100.100.10:22"))
	if err != nil {
		t.Fatalf("bound to tailscale0, the tailnet target: %v", err)
	}
	if !strings.HasPrefix(banner(ts), "SSH-2.0-") {
		t.Fatal("tailnet target sent no banner")
	}
	if _, err := netpolicy.DialInterface(ctx, "tailscale0", netip.MustParseAddrPort("[fd7a:115c:a1e0::10]:22")); err == nil {
		t.Log("IPv6 over the stand-in connected")
	} else {
		t.Logf("IPv6 over the stand-in (no IPv6 route there): %v", err)
	}
}
