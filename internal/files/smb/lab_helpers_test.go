package smb

// Helpers of the tests against the WebSSH test lab (tests/lab): Samba with
// the shares Secure, Plain and ReadOnly, and Windows Server 2025 with
// LabShare. Set WEBSSH_SMB_LAB to the lab.json of a running lab; set
// WEBSSH_SMB_LAB_NO_WINDOWS to leave out the Windows server. Without
// WEBSSH_SMB_LAB the lab tests skip.

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	json "encoding/json/v2"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/netpolicy"
)

type labTarget struct {
	name, share, domain, user, password string
	port                                int
	windows                             bool
	cipher                              uint16 // the cipher the server picks from our offer
	adminUser, adminPassword            string
	readerUser, readerPassword          string
}

func labSecret(t *testing.T, dir, rel string) string {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("lab secret: %v", err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Scan()
	return strings.TrimRight(s.Text(), "\r\n")
}

func labTargets(t *testing.T) []labTarget {
	t.Helper()
	path := os.Getenv("WEBSSH_SMB_LAB")
	if path == "" {
		t.Skip("set WEBSSH_SMB_LAB to the lab.json of a running test lab")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	type user struct {
		Username     string `json:"username"`
		Domain       string `json:"domain"`
		PasswordFile string `json:"password_file"`
	}
	var lab struct {
		Services struct {
			Samba struct {
				Port  int    `json:"port"`
				Users []user `json:"users"`
			} `json:"samba"`
			Windows struct {
				SMBPort int    `json:"smb_port"`
				Share   string `json:"share"`
				Users   []user `json:"users"`
			} `json:"windows"`
		} `json:"services"`
	}
	if err := json.Unmarshal(raw, &lab, json.RejectUnknownMembers(false)); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(path)
	secrets := map[string]user{}
	for _, u := range lab.Services.Samba.Users {
		secrets["samba-"+u.Username] = user{Username: u.Username, Domain: u.Domain, PasswordFile: labSecret(t, dir, u.PasswordFile)}
	}
	for _, u := range lab.Services.Windows.Users {
		secrets["windows-"+u.Username] = user{Username: u.Username, PasswordFile: labSecret(t, dir, u.PasswordFile)}
	}
	su, sr := secrets["samba-smbuser"], secrets["samba-smbreader"]
	out := []labTarget{
		{name: "samba-secure", share: "Secure", domain: su.Domain, user: su.Username, password: su.PasswordFile,
			port: lab.Services.Samba.Port, cipher: 0x2, readerUser: sr.Username, readerPassword: sr.PasswordFile},
		{name: "samba-plain", share: "Plain", domain: su.Domain, user: su.Username, password: su.PasswordFile,
			port: lab.Services.Samba.Port, cipher: 0x2},
	}
	if os.Getenv("WEBSSH_SMB_LAB_NO_WINDOWS") == "" && lab.Services.Windows.SMBPort != 0 {
		wu, wa := secrets["windows-smbuser"], secrets["windows-labadmin"]
		out = append(out, labTarget{name: "windows", share: lab.Services.Windows.Share, user: wu.Username,
			password: wu.PasswordFile, port: lab.Services.Windows.SMBPort, windows: true, cipher: 0x4,
			adminUser: wa.Username, adminPassword: wa.PasswordFile})
	}
	return out
}

// labConfig admits 127.0.0.1 with the default network policy (no target
// restriction) and dials port, or what dial returns.
func labConfig(t *testing.T, port int, dial func(ctx context.Context, network, addr string) (net.Conn, error)) Config {
	t.Helper()
	policy, err := netpolicy.New(netpolicy.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return Config{Network: policy, AllowedTargets: []string{"127.0.0.1"}, ConnectTimeout: 15 * time.Second,
		IOIdleTimeout: 15 * time.Second, Port: uint16(port), Dial: dial} // #nosec G115 -- lab ports
}

func (tg labTarget) target() Target {
	return Target{Host: "127.0.0.1", Share: tg.share, Domain: tg.domain, Username: tg.user, Password: []byte(tg.password)}
}

func connectLab(t *testing.T, tg labTarget, cfg *Config) *Backend {
	t.Helper()
	c := labConfig(t, tg.port, nil)
	if cfg != nil {
		c = *cfg
	}
	b, err := Connect(t.Context(), c, tg.target())
	if err != nil {
		t.Fatalf("%s: connect: %v (%+v)", tg.name, err, DiagnosticOf(err))
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

// labDir creates a fresh directory for one test and removes it after.
func labDir(t *testing.T, b *Backend) string {
	t.Helper()
	var token [6]byte
	_, _ = rand.Read(token[:])
	dir := "/go-fs3-" + hex.EncodeToString(token[:])
	if err := b.Mkdir(t.Context(), dir); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	t.Cleanup(func() {
		if b.dead.Load() {
			return
		}
		_ = b.Remove(context.Background(), dir, true, files.Budget{})
	})
	return dir
}

func wantCode(t *testing.T, err error, code fault.Code) {
	t.Helper()
	if got := fault.CodeOf(err); got != code {
		t.Fatalf("code %q, want %q (err %v)", got, code, err)
	}
}

func writeFile(t *testing.T, b *Backend, p, content string, o files.WriteOptions) files.WriteResult {
	t.Helper()
	if o.Size == 0 {
		o.Size = int64(len(content))
	}
	res, err := b.Write(t.Context(), p, strings.NewReader(content), o)
	if err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return res
}

func readFile(t *testing.T, b *Backend, p string) string {
	t.Helper()
	r, err := b.Open(t.Context(), p, files.Range{Length: -1})
	if err != nil {
		t.Fatalf("open %s: %v", p, err)
	}
	defer r.Close()
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return string(data)
}

func names(t *testing.T, b *Backend, dir string) []string {
	t.Helper()
	l, err := b.OpenListing(t.Context(), dir)
	if err != nil {
		t.Fatalf("list %s: %v", dir, err)
	}
	defer l.Close()
	var out []string
	for {
		page, more, err := l.Next(t.Context(), 100)
		if err != nil {
			t.Fatalf("list %s: %v", dir, err)
		}
		for _, e := range page {
			out = append(out, e.Name)
		}
		if !more {
			return out
		}
	}
}

// proxy forwards one TCP connection to the lab and can stop forwarding in
// either direction, to make the server look stalled. Bytes are held, not
// dropped, while a direction is paused.
type proxy struct {
	ln       net.Listener
	target   string
	up, down atomic.Bool // paused
	mu       sync.Mutex
	conns    []net.Conn
	dials    atomic.Int32
}

func newProxy(t *testing.T, port int) *proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &proxy{ln: ln, target: net.JoinHostPort("127.0.0.1", itoa(port))}
	t.Cleanup(func() { p.close() })
	go p.serve()
	return p
}

func itoa(n int) string { return strconv.Itoa(n) }

func (p *proxy) port() int { return p.ln.Addr().(*net.TCPAddr).Port }

func (p *proxy) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		s, err := net.Dial("tcp", p.target)
		if err != nil {
			_ = c.Close()
			continue
		}
		p.mu.Lock()
		p.conns = append(p.conns, c, s)
		p.mu.Unlock()
		go p.pump(s, c, &p.up)
		go p.pump(c, s, &p.down)
	}
}

func (p *proxy) pump(dst, src net.Conn, paused *atomic.Bool) {
	buf := make([]byte, 64<<10)
	for {
		n, err := src.Read(buf)
		for paused.Load() {
			time.Sleep(5 * time.Millisecond)
		}
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			_ = dst.Close()
			return
		}
	}
}

// dial counts the dials of the client and connects to the proxy.
func (p *proxy) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	p.dials.Add(1)
	return (&net.Dialer{}).DialContext(ctx, "tcp", p.ln.Addr().String())
}

func (p *proxy) close() {
	_ = p.ln.Close()
	p.up.Store(false)
	p.down.Store(false)
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		_ = c.Close()
	}
}

var errTest = errors.New("test source failed")

// failingReader returns n bytes and then fails.
type failingReader struct{ n int }

func (r *failingReader) Read(p []byte) (int, error) {
	if r.n <= 0 {
		return 0, errTest
	}
	k := min(len(p), r.n)
	for i := range k {
		p[i] = 'x'
	}
	r.n -= k
	return k, nil
}
