//go:build lab

// The lab tests run the SFTP backend over the shared dialer, the real
// network policy and host-key store against the shared test lab
// (tests/lab):
//
//	go test -tags lab -run Lab -v ./internal/files/sftp
//
// They fail, not skip, when the lab is not reachable. They work in a fresh
// directory below the home of pwuser and remove it afterwards.
package sftp_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	json "encoding/json/v2"
	"fmt"
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

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/files/sftp"
	"github.com/bifrost0x/webssh/internal/netpolicy"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/ssh/hostkey"
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
	p := os.Getenv("WEBSSH_LAB_JSON")
	if p == "" {
		p = filepath.Join("..", "..", "..", "tests", "lab", "runtime", "lab.json")
	}
	var l labFile
	raw, err := os.ReadFile(p)
	if err != nil {
		return l, err
	}
	return l, json.Unmarshal(raw, &l)
})

func lab(t testing.TB) labFile {
	t.Helper()
	l, err := loadLab()
	if err != nil {
		t.Fatalf("lab not available (set WEBSSH_LAB_JSON): %v", err)
	}
	return l
}

func secret(t testing.TB, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(lab(t).RuntimeDir, rel))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(raw))
}

func fingerprints(t testing.TB) map[string][]string {
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

// prompts accepts a first-contact host key only when the lab published
// its fingerprint, and counts the prompts (D-22: Quick SFTP asks).
type prompts struct {
	t    testing.TB
	fps  map[string][]string
	mu   sync.Mutex
	seen []client.HostKeyPrompt
}

func (p *prompts) HostKey(_ context.Context, q client.HostKeyPrompt) (bool, error) {
	p.mu.Lock()
	p.seen = append(p.seen, q)
	p.mu.Unlock()
	return slices.Contains(p.fps[q.Host+":"+strconv.Itoa(q.Port)], q.Fingerprint), nil
}

func (p *prompts) Banner(context.Context, client.BannerPrompt) (bool, error) { return true, nil }

type rig struct {
	quick *sftp.Quick
	ix    *prompts
	pw    string
}

func newRig(t testing.TB, o sftp.Options) *rig {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	policy, err := netpolicy.New(netpolicy.Config{Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	db := storetest.Open(t, hostkey.Schema())
	return &rig{
		quick: &sftp.Quick{Dialer: &client.Dialer{Net: policy, HostKeys: hostkey.New(db, logger)}, Options: o},
		ix:    &prompts{t: t, fps: fingerprints(t)}, pw: secret(t, "secrets/ssh-pwuser"),
	}
}

func (r *rig) modern(t testing.TB) client.Target {
	s := lab(t).Services["ssh-modern"]
	return client.Target{Hop: client.Hop{Host: s.Host, Port: s.Port, User: "pwuser", Auth: client.Auth{Password: r.pw}}}
}

func (r *rig) open(t testing.TB, tgt client.Target) *sftp.Backend {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, b, err := r.quick.Open(c, principal.Principal{UserID: 1, SessionID: "s"}, tgt, r.ix)
	if err != nil {
		t.Fatalf("quick sftp: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

// workdir creates a fresh directory below the login directory and removes
// it with everything in it when the test ends.
func workdir(t testing.TB, b *sftp.Backend) string {
	t.Helper()
	c := context.Background()
	home, err := b.Home(c)
	if err != nil {
		t.Fatal(err)
	}
	var tag [6]byte
	_, _ = rand.Read(tag[:])
	dir := fmt.Sprintf("%s/fs2-lab-%x", home, tag)
	if err := b.Mkdir(c, dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Remove(context.Background(), dir, true, files.Budget{MaxMembers: 100000}) })
	return dir
}

func write(t testing.TB, b *sftp.Backend, p string, data []byte, o files.WriteOptions) files.WriteResult {
	t.Helper()
	o.Size = int64(len(data))
	res, err := b.Write(context.Background(), p, bytes.NewReader(data), o)
	if err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return res
}

func read(t testing.TB, b *sftp.Backend, p string) []byte {
	t.Helper()
	rd, err := b.Open(context.Background(), p, files.Range{Length: -1})
	if err != nil {
		t.Fatalf("open %s: %v", p, err)
	}
	defer rd.Close()
	data, err := io.ReadAll(rd)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestLabQuickSFTP(t *testing.T) {
	r := newRig(t, sftp.Options{ChmodEnabled: true})
	b := r.open(t, r.modern(t))
	if len(r.ix.seen) != 1 || r.ix.seen[0].Role != client.RoleTarget {
		t.Fatalf("host key prompts %+v, want one for the unknown key (D-22)", r.ix.seen)
	}
	caps := b.Capabilities()
	if !caps.Ops.Has(files.CapChmod) || !slices.Contains(caps.Replace, files.StrategyAtomic) {
		t.Fatalf("capabilities %+v, extensions %v", caps, b.Extensions())
	}
	dir := workdir(t, b)
	c := context.Background()

	data := make([]byte, 5<<20+7)
	_, _ = rand.Read(data)
	res := write(t, b, dir+"/blob", data, files.WriteOptions{Exclusive: true})
	if got := read(t, b, dir+"/blob"); !bytes.Equal(got, data) || res.Revision != files.Revision(data) {
		t.Fatal("round trip differs")
	}

	// Chmod changes the object itself and never a link target.
	if err := b.Chmod(c, dir+"/blob", 0o600); err != nil {
		t.Fatal(err)
	}
	if e, _ := b.Stat(c, dir+"/blob", false); e.Mode&0o777 != 0o600 {
		t.Fatalf("mode %o", e.Mode)
	}
	// A replacement keeps the mode.
	write(t, b, dir+"/blob", []byte("small"), files.WriteOptions{})
	if e, _ := b.Stat(c, dir+"/blob", false); e.Mode&0o777 != 0o600 || e.Size != 5 {
		t.Fatalf("after replace %+v", e)
	}
	conf := []byte("listen 80;\n")
	write(t, b, dir+"/site.conf", conf, files.WriteOptions{})
	link := dir + "/enabled.conf"
	ln, err := exec(t, r, "ln -s "+dir+"/site.conf "+link)
	if err != nil {
		t.Fatalf("ln: %v %s", err, ln)
	}
	wantCode(t, b.Chmod(c, link, 0o600), fault.UnsupportedOperation)
	if e, _ := b.Stat(c, dir+"/site.conf", false); e.Mode&0o777 == 0o600 {
		t.Fatal("chmod followed the link")
	}
	// Stat(follow) names the canonical target (OpenSSH REALPATH), which
	// the file layer opens instead of the link.
	if e, err := b.Stat(c, link, true); err != nil || e.Path != dir+"/site.conf" || e.IsSymlink {
		t.Fatalf("stat follow: %+v %v", e, err)
	}
	// The editor saves through the link (OpenSSH REALPATH) and keeps it.
	edited := []byte("listen 8080;\n")
	if _, err := b.Write(c, link, bytes.NewReader(edited), files.WriteOptions{
		ExpectedRevision: files.Revision(conf), FollowSymlink: true, Size: int64(len(edited)),
	}); err != nil {
		t.Fatal(err)
	}
	if e, _ := b.Stat(c, link, false); !e.IsSymlink {
		t.Fatal("the link was replaced")
	}
	if got := read(t, b, dir+"/site.conf"); !bytes.Equal(got, edited) {
		t.Fatalf("target %q", got)
	}
	_, err = b.Write(c, link, bytes.NewReader(edited), files.WriteOptions{
		ExpectedRevision: files.Revision(conf), FollowSymlink: true, Size: int64(len(edited)),
	})
	wantCode(t, err, fault.EditConflict)

	// Paged listing over a large directory.
	if err := b.Mkdir(c, dir+"/many"); err != nil {
		t.Fatal(err)
	}
	if out, err := exec(t, r, "cd "+dir+"/many && for i in $(seq 1 1200); do : > f$i; done"); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	l, err := b.OpenListing(c, dir+"/many")
	if err != nil {
		t.Fatal(err)
	}
	total, pages := 0, 0
	for {
		entries, more, err := l.Next(c, 500)
		if err != nil {
			t.Fatal(err)
		}
		total += len(entries)
		pages++
		if !more {
			break
		}
	}
	if total != 1200 || pages != 3 {
		t.Fatalf("%d entries in %d pages", total, pages)
	}
	wantCode(t, b.Rename(c, dir+"/site.conf", dir+"/blob"), fault.FileConflict)
	if err := b.Remove(c, dir+"/many", true, files.Budget{}); err != nil {
		t.Fatal(err)
	}
	_ = b.Close()
	<-b.Done()
}

// exec runs a shell command as pwuser on ssh-modern through the dialer.
func exec(t testing.TB, r *rig, cmd string) (string, error) {
	t.Helper()
	d := r.quick.Dialer.(*client.Dialer)
	tgt := r.modern(t)
	tgt.Owner = 1
	conn, err := d.Dial(context.Background(), tgt, r.ix)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	var out, errOut bytes.Buffer
	status, err := conn.Exec(context.Background(), cmd, nil, &out, &errOut)
	if err == nil && status != 0 {
		err = fmt.Errorf("exit status %d", status)
	}
	return out.String() + errOut.String(), err
}

func wantCode(t testing.TB, err error, code fault.Code) {
	t.Helper()
	if !fault.Is(err, code) {
		t.Fatalf("got %v, want %s", err, code)
	}
}

func TestLabJumpChain(t *testing.T) {
	r := newRig(t, sftp.Options{})
	inner := lab(t).Services["ssh-inner"]
	bastion := lab(t).Services["ssh-bastion"]
	tgt := client.Target{
		Jumps: []client.Hop{{Host: bastion.Host, Port: bastion.Port, User: "pwuser", Auth: client.Auth{Password: r.pw}}},
		Hop:   client.Hop{Host: inner.InternalHost, Port: inner.InternalPort, User: "pwuser", Auth: client.Auth{Password: r.pw}},
	}
	b := r.open(t, tgt)
	dir := workdir(t, b)
	data := make([]byte, 8<<20)
	_, _ = rand.Read(data)
	write(t, b, dir+"/through-bastion", data, files.WriteOptions{Exclusive: true})
	if sha256.Sum256(read(t, b, dir+"/through-bastion")) != sha256.Sum256(data) {
		t.Fatal("round trip through the jump host differs")
	}
	roles := map[client.Role]int{}
	for _, q := range r.ix.seen {
		roles[q.Role]++
	}
	if roles[client.RoleJump] != 1 || roles[client.RoleTarget] != 1 {
		t.Fatalf("prompts by role %v", roles)
	}
}

func TestLabProbeAndSession(t *testing.T) {
	r := newRig(t, sftp.Options{})
	tgt := r.modern(t)
	tgt.Owner = 1
	conn, err := r.quick.Dialer.Dial(context.Background(), tgt, r.ix)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := sftp.Probe(context.Background(), conn, sftp.Options{}); err != nil {
		t.Fatalf("probe: %v", err)
	}
	open := sftp.SessionOpener(sessions{conn: conn}, sftp.Options{})
	d, b, err := open(context.Background(), principal.Principal{UserID: 1}, "term1")
	if err != nil {
		t.Fatal(err)
	}
	if d.Ephemeral || d.Protocol != "SFTP" || !strings.HasPrefix(d.Label, "pwuser@") {
		t.Fatalf("descriptor %+v", d)
	}
	_ = b.Close()
	// The terminal's connection stays open.
	if _, err := conn.Exec(context.Background(), "true", nil, nil, nil); err != nil {
		t.Fatalf("connection closed with the source: %v", err)
	}
}

type sessions struct{ conn *client.Conn }

func (s sessions) Session(context.Context, principal.Principal, string) (sftp.Session, error) {
	return sftp.Session{Conn: s.conn, Hop: client.Hop{Host: "ssh-modern", Port: 22, User: "pwuser"}}, nil
}

func TestLabLegacyServer(t *testing.T) {
	r := newRig(t, sftp.Options{})
	s := lab(t).Services["ssh-legacy"]
	b := r.open(t, client.Target{Hop: client.Hop{
		Host: s.Host, Port: s.Port, User: "legacyuser", Legacy: true,
		Auth: client.Auth{Password: secret(t, "secrets/ssh-legacyuser")},
	}})
	if !slices.Contains(b.Capabilities().Replace, files.StrategyAtomic) {
		t.Fatalf("extensions %v", b.Extensions())
	}
	dir := workdir(t, b)
	data := make([]byte, 3<<20)
	_, _ = rand.Read(data)
	write(t, b, dir+"/f", data, files.WriteOptions{Exclusive: true})
	write(t, b, dir+"/f", data[:100], files.WriteOptions{})
	if got := read(t, b, dir+"/f"); !bytes.Equal(got, data[:100]) {
		t.Fatal("round trip on the legacy server differs")
	}
}

// The terminal directory probe follows a shell on Debian (procps) and
// fails closed on Alpine, whose BusyBox ps lacks the needed options.
func TestLabTerminalDirectory(t *testing.T) {
	r := newRig(t, sftp.Options{})
	s := lab(t).Services["ssh-legacy"]
	tgt := client.Target{Owner: 1, Hop: client.Hop{
		Host: s.Host, Port: s.Port, User: "legacyuser", Legacy: true,
		Auth: client.Auth{Password: secret(t, "secrets/ssh-legacyuser")},
	}}
	conn, err := r.quick.Dialer.Dial(context.Background(), tgt, r.ix)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sh, err := conn.Shell(context.Background(), 24, 80)
	if err != nil {
		t.Fatal(err)
	}
	defer sh.Close()
	go func() { _, _ = io.Copy(io.Discard, sh) }()
	if _, err := io.WriteString(sh, "cd /usr/share\n"); err != nil {
		t.Fatal(err)
	}
	var d sftp.Directory
	for range 50 {
		if d, err = sftp.CollectDirectory(context.Background(), conn, ""); err == nil && d.Path == "/usr/share" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil || d.Path != "/usr/share" || !d.ShellReady || d.Shell == "" {
		t.Fatalf("legacy: %+v %v", d, err)
	}

	modern := r.modern(t)
	modern.Owner = 1
	mconn, err := r.quick.Dialer.Dial(context.Background(), modern, r.ix)
	if err != nil {
		t.Fatal(err)
	}
	defer mconn.Close()
	msh, err := mconn.Shell(context.Background(), 24, 80)
	if err != nil {
		t.Fatal(err)
	}
	defer msh.Close()
	go func() { _, _ = io.Copy(io.Discard, msh) }()
	if _, err := sftp.CollectDirectory(context.Background(), mconn, ""); err != sftp.ErrDirectoryUnsupported {
		t.Fatalf("busybox: %v", err)
	}
}

func TestLabSOCKS(t *testing.T) {
	r := newRig(t, sftp.Options{})
	proxy := lab(t).Services["socks-open"]
	inner := lab(t).Services["ssh-inner"]
	b := r.open(t, client.Target{
		Proxy: &client.SOCKS{Host: proxy.Host, Port: proxy.Port, RemoteDNS: true},
		Hop:   client.Hop{Host: inner.InternalHost, Port: inner.InternalPort, User: "pwuser", Auth: client.Auth{Password: r.pw}},
	})
	dir := workdir(t, b)
	write(t, b, dir+"/via-socks", []byte("hello"), files.WriteOptions{Exclusive: true})
	if got := read(t, b, dir+"/via-socks"); string(got) != "hello" {
		t.Fatalf("%q", got)
	}
}
