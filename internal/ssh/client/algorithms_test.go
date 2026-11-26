package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/netpolicy"
)

func TestAlgorithmsExcludeLegacyByDefault(t *testing.T) {
	never := []string{ssh.InsecureKeyExchangeDH1SHA1, keyAlgoDSA, "aes192-cbc", "aes256-cbc", "hmac-md5", "hmac-md5-96", ssh.InsecureHMACSHA196, "arcfour", "arcfour128", "arcfour256"}
	legacyOnly := []string{ssh.KeyAlgoRSA, ssh.InsecureKeyExchangeDH14SHA1, ssh.InsecureKeyExchangeDHGEXSHA1, ssh.InsecureCipherAES128CBC, ssh.InsecureCipherTripleDESCBC}
	plain, legacy := Algorithms(false), Algorithms(true)
	all := func(a ssh.Algorithms) []string {
		return slices.Concat(a.KeyExchanges, a.Ciphers, a.MACs, a.HostKeys)
	}
	for _, bad := range slices.Concat(never, legacyOnly) {
		if slices.Contains(all(plain), bad) {
			t.Errorf("%s offered without the legacy setting", bad)
		}
	}
	for _, bad := range never {
		if slices.Contains(all(legacy), bad) {
			t.Errorf("%s offered with the legacy setting", bad)
		}
	}
	// D-01: legacy algorithms come last, after every modern one.
	for _, pair := range [][2][]string{
		{plain.KeyExchanges, legacy.KeyExchanges}, {plain.Ciphers, legacy.Ciphers}, {plain.HostKeys, legacy.HostKeys},
	} {
		if !slices.Equal(pair[0], pair[1][:len(pair[0])]) || len(pair[1]) <= len(pair[0]) {
			t.Errorf("legacy list %v does not extend %v at the end", pair[1], pair[0])
		}
	}
	for _, a := range plain.HostKeys {
		if a == ssh.KeyAlgoRSA || bytes.Contains([]byte(a), []byte("cert")) || bytes.Contains([]byte(a), []byte("mldsa")) {
			t.Errorf("host key algorithm %s offered", a)
		}
	}
}

func rsaSigner(t *testing.T) ssh.Signer {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// M8: an RSA key never signs with SHA-1 without the legacy setting, even
// when the server accepts nothing else; with the setting it does.
func TestRSAKeyNeverSignsSHA1WithoutLegacy(t *testing.T) {
	key := rsaSigner(t)
	accepted := 0
	s := startServer(t, &ssh.ServerConfig{
		PublicKeyAuthAlgorithms: []string{ssh.KeyAlgoRSA},
		PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if !bytes.Equal(k.Marshal(), key.PublicKey().Marshal()) {
				return nil, errors.New("unknown key")
			}
			accepted++
			return nil, nil
		},
	})
	d, _ := newDialer(trusting(s), keyMap{"rsa": key})
	tgt := target(s, "u", Auth{KeyID: "rsa"})
	if _, err := d.Dial(t.Context(), tgt, nil); fault.CodeOf(err) != fault.AuthFailed || accepted != 0 {
		t.Fatalf("without legacy: %v, %d signatures accepted", err, accepted)
	}
	tgt.Hop.Legacy = true
	c, err := d.Dial(t.Context(), tgt, nil)
	if err != nil {
		t.Fatalf("with legacy: %v", err)
	}
	_ = c.Close()

	restricted, err := restrictSigner(key, false)
	if err != nil {
		t.Fatal(err)
	}
	if algos := restricted.(ssh.MultiAlgorithmSigner).Algorithms(); slices.Contains(algos, ssh.KeyAlgoRSA) {
		t.Fatalf("restricted signer allows %v", algos)
	}
}

// plainSigner hides the AlgorithmSigner methods of a key.
type plainSigner struct{ s ssh.Signer }

func (p plainSigner) PublicKey() ssh.PublicKey { return p.s.PublicKey() }
func (p plainSigner) Sign(r io.Reader, data []byte) (*ssh.Signature, error) {
	return p.s.Sign(r, data)
}

// restrictSigner fails closed: an RSA signer that cannot be restricted is
// not used at all.
func TestRestrictSignerFailsClosed(t *testing.T) {
	key := plainSigner{rsaSigner(t)}
	for _, legacy := range []bool{false, true} {
		if _, err := restrictSigner(key, legacy); !errors.Is(err, errSignerAlgorithms) {
			t.Fatalf("legacy=%v: %v", legacy, err)
		}
	}
	if _, err := sha1Signer(key); !errors.Is(err, errSignerAlgorithms) {
		t.Fatal(err)
	}
	called := 0
	s := startServer(t, &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
		called++
		return nil, nil
	}})
	d, _ := newDialer(trusting(s), keyMap{"rsa": key})
	if _, err := d.Dial(t.Context(), target(s, "u", Auth{KeyID: "rsa"}), nil); err == nil || called != 0 {
		t.Fatalf("got %v, server saw %d attempts", err, called)
	}
	// Non-RSA keys are used as they are.
	ed := clientKey(t)
	if got, err := restrictSigner(ed, false); err != nil || got != ed {
		t.Fatalf("ed25519: %v", err)
	}
}

// The dialer goes through the real network policy: BLOCK_INTERNAL_SSH
// refuses the target before any packet, and on a tailnet node a relay on
// loopback is refused while a loopback target is not.
func TestDialerUsesNetworkPolicy(t *testing.T) {
	calls := 0
	s := startServer(t, passwordServer("u", "pw", &calls))
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	blocked, err := netpolicy.New(netpolicy.Config{BlockInternal: true, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	d := &Dialer{Net: blocked, HostKeys: trusting(s), Keepalive: -1}
	_, err = d.Dial(t.Context(), target(s, "u", Auth{Password: "pw"}), nil)
	if role, code := hopOf(t, err); role != RoleTarget || code != fault.TargetBlocked || calls != 0 {
		t.Fatalf("blocked target: %s %s, %d attempts", role, code, calls)
	}

	node, err := netpolicy.New(netpolicy.Config{Logger: quiet, Tailnet: netpolicy.Tailnet{
		Interface: "tailscale0", InterfacePresent: func(string) bool { return true },
		Lookup: func(_ context.Context, addr netip.Addr) (netpolicy.Route, error) {
			return netpolicy.Route{Interface: "lo", Local: addr.IsLoopback()}, nil
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	d = &Dialer{Net: node, HostKeys: trusting(s), Keepalive: -1}
	c, err := d.Dial(t.Context(), target(s, "u", Auth{Password: "pw"}), nil)
	if err != nil {
		t.Fatalf("loopback target on a tailnet node: %v", err)
	}
	_ = c.Close()
	viaJump := target(s, "u", Auth{Password: "pw"})
	viaJump.Jumps = []Hop{{Host: s.host, Port: s.port, User: "u", Auth: Auth{Password: "pw"}}}
	_, err = d.Dial(t.Context(), viaJump, nil)
	if role, _ := hopOf(t, err); role != RoleJump || !errors.Is(err, netpolicy.ErrTailnetRestricted) {
		t.Fatalf("loopback jump host on a tailnet node: %v", err)
	}
	viaSOCKS := target(s, "u", Auth{Password: "pw"})
	viaSOCKS.Proxy = &SOCKS{Host: "127.0.0.1", Port: 1080}
	_, err = d.Dial(t.Context(), viaSOCKS, nil)
	if role, _ := hopOf(t, err); role != RoleSOCKS || !errors.Is(err, netpolicy.ErrTailnetRestricted) {
		t.Fatalf("loopback SOCKS5 proxy on a tailnet node: %v", err)
	}
	behind := target(s, "u", Auth{Password: "pw"})
	behind.Hop.Host = "box.tail1234.ts.net"
	behind.Proxy = &SOCKS{Host: "192.0.2.1", Port: 1080, RemoteDNS: true}
	_, err = d.Dial(t.Context(), behind, nil)
	if role, _ := hopOf(t, err); role != RoleTarget || !errors.Is(err, netpolicy.ErrTailnetRestricted) {
		t.Fatalf("MagicDNS name behind SOCKS5: %v", err)
	}
}
