//go:build lab

// The lab tests run the dialer with the real network policy and host-key
// store against the shared test lab (tests/lab). Run them with
//
//	go test -tags lab -run Lab ./internal/ssh/client
//
// They fail, not skip, when the lab is not reachable: a lab run that tested
// nothing must not look green.
package client_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	json "encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/netpolicy"
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/ssh/hostkey"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

type labService struct {
	Host         string            `json:"host"`
	Port         int               `json:"port"`
	InternalHost string            `json:"internal_host"`
	InternalPort int               `json:"internal_port"`
	Fingerprints map[string]string `json:"host_key_fingerprints"`
	FPFile       string            `json:"host_key_fingerprints_file"`
}

type labFile struct {
	RuntimeDir string                `json:"runtime_dir"`
	Services   map[string]labService `json:"services"`
}

var loadLab = sync.OnceValues(func() (labFile, error) {
	path := os.Getenv("WEBSSH_LAB_JSON")
	if path == "" {
		path = filepath.Join("..", "..", "..", "tests", "lab", "runtime", "lab.json")
	}
	var l labFile
	raw, err := os.ReadFile(path)
	if err != nil {
		return l, err
	}
	return l, json.Unmarshal(raw, &l)
})

func lab(t *testing.T) labFile {
	t.Helper()
	l, err := loadLab()
	if err != nil {
		t.Fatalf("lab not available (set WEBSSH_LAB_JSON): %v", err)
	}
	return l
}

func secret(t *testing.T, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(lab(t).RuntimeDir, rel))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(raw))
}

func service(t *testing.T, name string) labService {
	t.Helper()
	s, ok := lab(t).Services[name]
	if !ok {
		t.Fatalf("lab has no %s", name)
	}
	return s
}

// fingerprints maps host:port, under every name a lab host is reached by,
// to the fingerprints lab.json publishes.
func fingerprints(t *testing.T) map[string][]string {
	t.Helper()
	l := lab(t)
	out := map[string][]string{}
	for _, s := range l.Services {
		fps := s.Fingerprints
		if s.FPFile != "" {
			if raw, err := os.ReadFile(filepath.Join(l.RuntimeDir, s.FPFile)); err == nil {
				_ = json.Unmarshal(raw, &fps)
			}
		}
		var list []string
		for _, fp := range fps {
			list = append(list, fp)
		}
		if s.Host != "" {
			out[s.Host+":"+strconv.Itoa(s.Port)] = list
		}
		out[s.InternalHost+":"+strconv.Itoa(s.InternalPort)] = list
	}
	return out
}

// labPrompts accepts a first-contact host key only when its fingerprint is
// the one the lab published, which also checks the fingerprint format.
type labPrompts struct {
	t    *testing.T
	fps  map[string][]string
	mu   sync.Mutex
	seen []client.HostKeyPrompt
}

func (p *labPrompts) HostKey(_ context.Context, q client.HostKeyPrompt) (bool, error) {
	p.mu.Lock()
	p.seen = append(p.seen, q)
	p.mu.Unlock()
	if slices.Contains(p.fps[q.Host+":"+strconv.Itoa(q.Port)], q.Fingerprint) {
		return true, nil
	}
	p.t.Errorf("unexpected host key for %s:%d: %s %s", q.Host, q.Port, q.KeyType, q.Fingerprint)
	return false, nil
}

func (p *labPrompts) Banner(context.Context, client.BannerPrompt) (bool, error) { return true, nil }

// recordingKeys keeps the keys the store recorded, for the revocation test.
type recordingKeys struct {
	*hostkey.Store
	mu   sync.Mutex
	keys []ssh.PublicKey
}

func (r *recordingKeys) Record(ctx context.Context, owner int64, host string, port int, key ssh.PublicKey) error {
	r.mu.Lock()
	r.keys = append(r.keys, key)
	r.mu.Unlock()
	return r.Store.Record(ctx, owner, host, port, key)
}

type signers map[string]ssh.Signer

func (s signers) Signer(_ context.Context, _ int64, id string) (ssh.Signer, error) {
	if k, ok := s[id]; ok {
		return k, nil
	}
	return nil, fault.New(fault.NotFound, "")
}

type rig struct {
	dialer *client.Dialer
	keys   *recordingKeys
	db     *store.DB
	ix     *labPrompts
	signer signers
}

func newRig(t *testing.T, cfg netpolicy.Config) *rig {
	t.Helper()
	cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	policy, err := netpolicy.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	db := storetest.Open(t, hostkey.Schema())
	r := &rig{db: db, keys: &recordingKeys{Store: hostkey.New(db, cfg.Logger)}, ix: &labPrompts{t: t, fps: fingerprints(t)}, signer: signers{}}
	r.dialer = &client.Dialer{Net: policy, HostKeys: r.keys, Keys: r.signer}
	return r
}

func hop(t *testing.T, name, user string, auth client.Auth) client.Hop {
	s := service(t, name)
	return client.Hop{Host: s.Host, Port: s.Port, User: user, Auth: auth}
}

func innerHop(t *testing.T, name, user string, auth client.Auth) client.Hop {
	s := service(t, name)
	return client.Hop{Host: s.InternalHost, Port: s.InternalPort, User: user, Auth: auth}
}

// whoami runs `id -un` in an interactive shell and returns the answer.
func whoami(t *testing.T, r *rig, tgt client.Target) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	sh, err := r.dialer.OpenShell(ctx, tgt, r.ix, 24, 80)
	if err != nil {
		t.Fatalf("open shell: %v", err)
	}
	defer func() { _ = sh.Close() }()
	if _, err := io.WriteString(sh, "echo WHO=$(id -un)=; exit\n"); err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(io.LimitReader(sh, 1<<20))
	text := string(out)
	i := strings.LastIndex(text, "WHO=")
	if i < 0 {
		t.Fatalf("no answer in %q", text)
	}
	return strings.SplitN(text[i+4:], "=", 2)[0]
}

func code(err error) fault.Code { return fault.CodeOf(err) }

func TestLabPasswordAndKeys(t *testing.T) {
	r := newRig(t, netpolicy.Config{})
	tgt := client.Target{Owner: 1, Hop: hop(t, "ssh-modern", "pwuser", client.Auth{Password: secret(t, "secrets/ssh-pwuser")})}
	if got := whoami(t, r, tgt); got != "pwuser" {
		t.Fatalf("pwuser: %q", got)
	}
	keyDir := filepath.Join(lab(t).RuntimeDir, "ssh", "client")
	for _, name := range []string{"ecdsa-p256", "ecdsa-p256-pem", "ecdsa-p384", "ecdsa-p521", "ed25519", "ed25519-encrypted", "rsa-3072", "rsa-3072-pem", "rsa-3072-pem-encrypted", "rsa-3072-pkcs8"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(keyDir, name))
			if err != nil {
				t.Fatal(err)
			}
			var passphrase []byte
			if strings.HasSuffix(name, "-encrypted") {
				passphrase = []byte(secret(t, "secrets/ssh-key-"+name+"-passphrase"))
			}
			r.signer[name] = labSigner(t, raw, passphrase)
			tgt := client.Target{Owner: 1, Hop: hop(t, "ssh-modern", "keyuser", client.Auth{KeyID: name})}
			if got := whoami(t, r, tgt); got != "keyuser" {
				t.Fatalf("keyuser: %q", got)
			}
		})
	}
	if len(r.ix.seen) != 1 {
		t.Fatalf("host key prompts: %d, want one for the first contact", len(r.ix.seen))
	}
}

// keyboard-interactive: the saved password answers the first hidden prompt;
// the one-time code is never guessed, so the attempt ends cleanly.
func TestLabKeyboardInteractive(t *testing.T) {
	r := newRig(t, netpolicy.Config{})
	for _, user := range []string{"kiuser", "mfauser"} {
		auth := client.Auth{Password: secret(t, "secrets/ssh-"+user)}
		if user == "mfauser" {
			raw, err := os.ReadFile(filepath.Join(lab(t).RuntimeDir, "ssh", "client", "ed25519"))
			if err != nil {
				t.Fatal(err)
			}
			r.signer["mfa"] = labSigner(t, raw, nil)
			auth.KeyID = "mfa"
		}
		tgt := client.Target{Owner: 1, Hop: hop(t, "ssh-modern", user, auth)}
		if _, err := r.dialer.Dial(t.Context(), tgt, r.ix); code(err) != fault.NotAvailableInPreview {
			t.Errorf("%s attended: %v", user, err)
		}
		if _, err := r.dialer.Dial(t.Context(), tgt, nil); code(err) != fault.InteractionRequired {
			t.Errorf("%s unattended: %v", user, err)
		}
		// PAM asks for the code before it reveals a wrong password, so a
		// wrong password ends the same way; the code is never answered.
		tgt.Hop.Auth.Password = "wrong"
		tgt.Hop.Auth.KeyID = ""
		if _, err := r.dialer.Dial(t.Context(), tgt, r.ix); err == nil {
			t.Errorf("%s wrong password accepted", user)
		}
	}
}

func TestLabJumpHosts(t *testing.T) {
	r := newRig(t, netpolicy.Config{})
	pw := secret(t, "secrets/ssh-pwuser")
	tgt := client.Target{Owner: 1,
		Jumps: []client.Hop{hop(t, "ssh-bastion", "pwuser", client.Auth{Password: pw})},
		Hop:   innerHop(t, "ssh-inner", "pwuser", client.Auth{Password: pw}),
	}
	if got := whoami(t, r, tgt); got != "pwuser" {
		t.Fatalf("through bastion: %q", got)
	}
	// Two jump hosts: the bastion, then the bastion again by its inner name.
	tgt.Jumps = append(tgt.Jumps, innerHop(t, "ssh-bastion", "pwuser", client.Auth{Password: pw}))
	if got := whoami(t, r, tgt); got != "pwuser" {
		t.Fatalf("through two jump hosts: %q", got)
	}
	roles := map[client.Role]int{}
	for _, q := range r.ix.seen {
		roles[q.Role]++
	}
	if roles[client.RoleJump] != 2 || roles[client.RoleTarget] != 1 {
		t.Fatalf("prompts by role %v", roles)
	}
	tgt.Hop.Port = 2
	_, err := r.dialer.Dial(t.Context(), tgt, r.ix)
	if he, _ := errors.AsType[*client.HopError](err); he == nil || he.Role != client.RoleTarget || code(err) != fault.ChannelRejected {
		t.Fatalf("unreachable target behind the jump host: %v", err)
	}
	// With BLOCK_INTERNAL_SSH the loopback bastion is refused before
	// anything is sent.
	blocked := newRig(t, netpolicy.Config{BlockInternal: true})
	if _, err := blocked.dialer.Dial(t.Context(), tgt, blocked.ix); code(err) != fault.TargetBlocked || len(blocked.ix.seen) != 0 {
		t.Fatalf("blocked: %v", err)
	}
}

func TestLabSOCKS(t *testing.T) {
	r := newRig(t, netpolicy.Config{})
	pw := secret(t, "secrets/ssh-pwuser")
	open := service(t, "socks-open")
	tgt := client.Target{Owner: 1, Hop: innerHop(t, "ssh-inner", "pwuser", client.Auth{Password: pw}),
		Proxy: &client.SOCKS{Host: open.Host, Port: open.Port, RemoteDNS: true}}
	if got := whoami(t, r, tgt); got != "pwuser" {
		t.Fatalf("through socks-open: %q", got)
	}
	// Without remote DNS the inner name does not resolve here.
	tgt.Proxy.RemoteDNS = false
	if _, err := r.dialer.Dial(t.Context(), tgt, r.ix); code(err) != fault.Unreachable {
		t.Fatalf("local DNS for a lab-only name: %v", err)
	}
	auth := service(t, "socks-auth")
	tgt.Proxy = &client.SOCKS{Host: auth.Host, Port: auth.Port, RemoteDNS: true}
	_, err := r.dialer.Dial(t.Context(), tgt, r.ix)
	if he, _ := errors.AsType[*client.HopError](err); he == nil || he.Role != client.RoleSOCKS || he.Detail != "socks_auth_required" {
		t.Fatalf("proxy with login: %v", err)
	}
	// RFC 1929 login (C-CONN-08).
	tgt.Proxy.Username, tgt.Proxy.Password = "labproxy", secret(t, "secrets/socks-labproxy")
	if got := whoami(t, r, tgt); got != "pwuser" {
		t.Fatalf("through socks-auth with login: %q", got)
	}
	tgt.Proxy.Password = "wrong"
	_, err = r.dialer.Dial(t.Context(), tgt, r.ix)
	if he, _ := errors.AsType[*client.HopError](err); he == nil || he.Role != client.RoleSOCKS || code(err) != fault.SOCKSAuthFailed {
		t.Fatalf("wrong proxy password: %v", err)
	}
	// The open proxy offers no login method.
	tgt.Proxy = &client.SOCKS{Host: open.Host, Port: open.Port, RemoteDNS: true, Username: "labproxy", Password: "x"}
	if _, err := r.dialer.Dial(t.Context(), tgt, r.ix); code(err) != fault.SOCKSAuthRejected {
		t.Fatalf("login offered to a proxy without login: %v", err)
	}
	// A proxy that is down has its own code since the socks_* codes of the
	// Python release are in the catalog.
	tgt.Proxy = &client.SOCKS{Host: "127.0.0.1", Port: 1, RemoteDNS: true}
	if _, err := r.dialer.Dial(t.Context(), tgt, r.ix); code(err) != fault.SOCKSProxyUnreachable {
		t.Fatalf("proxy down: %v", err)
	}
}

func TestLabLegacyServer(t *testing.T) {
	r := newRig(t, netpolicy.Config{})
	tgt := client.Target{Owner: 1, Hop: hop(t, "ssh-legacy", "legacyuser", client.Auth{Password: secret(t, "secrets/ssh-legacyuser")})}
	if _, err := r.dialer.Dial(t.Context(), tgt, r.ix); code(err) != fault.NoCommonAlgorithm {
		t.Fatalf("without the legacy setting: %v", err)
	}
	tgt.Hop.Legacy = true
	if got := whoami(t, r, tgt); got != "legacyuser" {
		t.Fatalf("with the legacy setting: %q", got)
	}
	raw, err := os.ReadFile(filepath.Join(lab(t).RuntimeDir, "ssh", "legacy", "client", "rsa-2048-pem"))
	if err != nil {
		t.Fatal(err)
	}
	r.signer["legacy-rsa"] = labSigner(t, raw, nil)
	tgt.Hop.Auth = client.Auth{KeyID: "legacy-rsa"}
	if got := whoami(t, r, tgt); got != "legacyuser" {
		t.Fatalf("RSA key with the legacy setting: %q", got)
	}
	tgt.Hop.Legacy = false
	if _, err := r.dialer.Dial(t.Context(), tgt, r.ix); err == nil {
		t.Fatal("RSA key without the legacy setting")
	}
}

// labSigner reads a lab client key. The dialer only receives signers;
// parsing and checking uploaded keys is the vault's (its lab test covers
// the same files and the DSA key).
func labSigner(t *testing.T, raw, passphrase []byte) ssh.Signer {
	t.Helper()
	var (
		signer ssh.Signer
		err    error
	)
	if passphrase != nil {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(raw, passphrase)
	} else {
		signer, err = ssh.ParsePrivateKey(raw)
	}
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func TestLabHostKeys(t *testing.T) {
	r := newRig(t, netpolicy.Config{})
	tgt := client.Target{Owner: 1, Hop: hop(t, "ssh-modern", "pwuser", client.Auth{Password: secret(t, "secrets/ssh-pwuser")})}
	c, err := r.dialer.Dial(t.Context(), tgt, r.ix)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	c, err = r.dialer.Dial(t.Context(), tgt, nil)
	if err != nil || len(r.ix.seen) != 1 {
		t.Fatalf("second contact needs no prompt: %v, %d prompts", err, len(r.ix.seen))
	}
	_ = c.Close()
	// Another user has no trust for this host yet.
	other := tgt
	other.Owner = 2
	if _, err := r.dialer.Dial(t.Context(), other, nil); code(err) != fault.HostKeyNotAccepted {
		t.Fatalf("another user without a prompt: %v", err)
	}
	// The administrator revokes the key globally.
	seen := r.keys.keys[0]
	name := "[" + tgt.Hop.Host + "]:" + strconv.Itoa(tgt.Hop.Port)
	revoked := newRig(t, netpolicy.Config{})
	if err := revoked.db.Write(t.Context(), func(tx *store.Tx) error {
		return hostkey.ImportFile(t.Context(), tx, hostkey.ScopeGlobal, 0, []byte("@revoked "+hostkey.FormatLine(name, seen)), time.Now())
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := revoked.dialer.Dial(t.Context(), tgt, revoked.ix); code(err) != fault.HostKeyRevoked || len(revoked.ix.seen) != 0 {
		t.Fatalf("revoked: %v", err)
	}
	// A different key of the same type is stored: refused without a prompt.
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	fake, _ := ssh.NewPublicKey(pub)
	changed := newRig(t, netpolicy.Config{})
	if err := changed.keys.Record(t.Context(), 1, tgt.Hop.Host, tgt.Hop.Port, fake); err != nil {
		t.Fatal(err)
	}
	if _, err := changed.dialer.Dial(t.Context(), tgt, changed.ix); code(err) != fault.HostKeyChanged || len(changed.ix.seen) != 0 {
		t.Fatalf("changed: %v", err)
	}
}

// A forced re-key in the middle of a session keeps the session: the
// host-key check of the new key exchange runs after the handshake context
// ended and must accept the pinned key.
func TestLabRekey(t *testing.T) {
	r := newRig(t, netpolicy.Config{})
	r.dialer.RekeyThreshold = 4 << 10
	tgt := client.Target{Owner: 1, Hop: hop(t, "ssh-modern", "pwuser", client.Auth{Password: secret(t, "secrets/ssh-pwuser")})}
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	sh, err := r.dialer.OpenShell(ctx, tgt, r.ix, 24, 80)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sh.Close() }()
	if _, err := io.WriteString(sh, "seq 1 20000; echo END=$((6*7)); exit\n"); err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(io.LimitReader(sh, 8<<20))
	if !strings.Contains(string(out), "\n20000\r\n") || !strings.Contains(string(out), "END=42") {
		t.Fatalf("session ended early after %d bytes (re-key every 4 KiB)", len(out))
	}
	if len(r.ix.seen) != 1 {
		t.Fatalf("re-key prompted again: %d prompts", len(r.ix.seen))
	}
}

// bannerPrompts trusts every host key (the banner server is a throwaway
// container) and answers banners with accept.
type bannerPrompts struct {
	accept bool
	seen   []client.BannerPrompt
}

func (*bannerPrompts) HostKey(context.Context, client.HostKeyPrompt) (bool, error) { return true, nil }

func (b *bannerPrompts) Banner(_ context.Context, q client.BannerPrompt) (bool, error) {
	b.seen = append(b.seen, q)
	return b.accept, nil
}

// TestLabBanner runs against the OpenSSH server of testdata/banner-lab.sh:
// the banner reaches the user cleaned of control characters, accepting it
// signs in, declining it or connecting unattended ends the attempt.
func TestLabBanner(t *testing.T) {
	addr, password := os.Getenv("WEBSSH_BANNER_ADDR"), os.Getenv("WEBSSH_BANNER_PASSWORD")
	if addr == "" {
		t.Fatal("run with testdata/banner-lab.sh (WEBSSH_BANNER_ADDR)")
	}
	host, portText, _ := strings.Cut(addr, ":")
	port, _ := strconv.Atoi(portText)
	policy, err := netpolicy.New(netpolicy.Config{Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{dialer: &client.Dialer{Net: policy, HostKeys: hostkey.New(storetest.Open(t, hostkey.Schema()), nil)}}
	tgt := client.Target{Owner: 1, Hop: client.Hop{Host: host, Port: port, User: "pwuser", Auth: client.Auth{Password: password}}}
	ix := &bannerPrompts{accept: true}
	c, err := r.dialer.Dial(t.Context(), tgt, ix)
	if err != nil {
		t.Fatalf("accepted banner: %v", err)
	}
	_ = c.Close()
	if len(ix.seen) != 1 {
		t.Fatalf("banner prompts: %d", len(ix.seen))
	}
	q := ix.seen[0]
	if q.Role != client.RoleTarget || q.Port != port || !strings.Contains(q.Banner, "Authorized use only.") ||
		!strings.Contains(q.Banner, "Grüße") || strings.ContainsAny(q.Banner, "\x1b\a") {
		t.Fatalf("banner prompt %+v, text %+q", q, q.Banner)
	}
	t.Logf("banner as shown: %+q", q.Banner)
	if _, err := r.dialer.Dial(t.Context(), tgt, &bannerPrompts{accept: false}); code(err) != fault.BannerDeclined {
		t.Fatalf("declined banner: %v", err)
	}
	if _, err := r.dialer.Dial(t.Context(), tgt, nil); code(err) != fault.BannerDeclined {
		t.Fatalf("unattended banner: %v", err)
	}
}
