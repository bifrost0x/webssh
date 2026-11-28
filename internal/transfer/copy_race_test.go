package transfer

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pkgsftp "github.com/pkg/sftp"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files/sftp"
)

// raceChan calls hook with the type and first path of every request
// before it reaches the server (see internal/files/sftp/race_harness_test.go).
type raceChan struct {
	io.Reader
	w    io.WriteCloser
	hook func(typ byte, p string)
	mu   sync.Mutex
	buf  []byte
}

func (h *raceChan) Write(p []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.buf = append(h.buf, p...)
	for len(h.buf) >= 4 {
		n := int(binary.BigEndian.Uint32(h.buf))
		if len(h.buf) < 4+n {
			break
		}
		if body := h.buf[4 : 4+n]; len(body) >= 9 && body[0] != 1 {
			if l := int(binary.BigEndian.Uint32(body[5:9])); 9+l <= len(body) {
				h.hook(body[0], string(body[9:9+l]))
			}
		}
		if _, err := h.w.Write(h.buf[:4+n]); err != nil {
			return 0, err
		}
		h.buf = h.buf[4+n:]
	}
	return len(p), nil
}

func (h *raceChan) Close() error { return h.w.Close() }

const (
	pktLstat   = 7
	pktOpendir = 11
	pktClose   = 4
)

// raceBackend opens an SFTP backend through hook: on OpenSSH's
// sftp-server (REALPATH resolves links) or on pkg/sftp's server.
func raceBackend(t *testing.T, openssh bool, hook func(typ byte, p string)) *sftp.Backend {
	t.Helper()
	var ch *raceChan
	if openssh {
		bin := "/usr/lib/ssh/sftp-server"
		if _, err := os.Stat(bin); err != nil {
			bin = "/usr/lib/openssh/sftp-server"
			if _, err := os.Stat(bin); err != nil {
				t.Skip("OpenSSH sftp-server not installed")
			}
		}
		cmd := exec.Command(bin, "-e")
		in, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = in.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
		ch = &raceChan{Reader: out, w: in, hook: hook}
	} else {
		srvSide, cli := net.Pipe()
		srv, err := pkgsftp.NewServer(srvSide)
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = srv.Serve() }()
		t.Cleanup(func() { _ = srv.Close() })
		ch = &raceChan{Reader: cli, w: cli, hook: hook}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	b, err := sftp.Open(ctx, ch, sftp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func firstMatch(match func(typ byte, p string) bool, fn func()) func(byte, string) {
	var once sync.Once
	return func(typ byte, p string) {
		if match(typ, p) {
			once.Do(fn)
		}
	}
}

func relink(t *testing.T, dir, park, target string) {
	t.Helper()
	if err := os.Rename(dir, park); err != nil {
		t.Error(err)
	} else if err := os.Symlink(target, dir); err != nil {
		t.Error(err)
	}
}

func raceBase(t *testing.T) string {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return base
}

func mkfile(t *testing.T, p, data string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
}

// A destination directory replaced by a link after the copy created it
// does not lead the copy into the link target.
func TestCopyRefusesSwappedDestinationDirectory(t *testing.T) {
	base := raceBase(t)
	victim := filepath.Join(base, "home-alice", ".ssh")
	mkfile(t, filepath.Join(victim, "authorized_keys"), "alice\n", 0o600)
	src := filepath.Join(base, "src", "kit")
	mkfile(t, filepath.Join(src, "conf", "authorized_keys"), "mallory\n", 0o644)
	mkfile(t, filepath.Join(src, "conf", "rc"), "mallory\n", 0o644)
	dst := filepath.Join(base, "shared", "drop")
	if err := os.MkdirAll(filepath.Join(dst, "conf"), 0o777); err != nil {
		t.Fatal(err)
	}
	b := raceBackend(t, true, firstMatch(func(typ byte, p string) bool {
		return typ == pktLstat && strings.HasPrefix(p, filepath.Join(dst, "conf")+"/")
	}, func() { relink(t, filepath.Join(dst, "conf"), filepath.Join(base, "parked"), victim) }))
	cp := &copier{src: b, dst: b, replace: true, chunk: 64 << 10,
		bud: &budget{maxBytes: 1 << 20, maxMembers: 100, maxDepth: 10}}
	err := cp.run(t.Context(), src, dst)
	for _, n := range []string{"authorized_keys", "rc"} {
		if got, _ := os.ReadFile(filepath.Join(victim, n)); strings.Contains(string(got), "mallory") {
			t.Errorf("%s of the victim written through the swapped directory", n)
		}
	}
	if !fault.Is(err, fault.SourceChanged) {
		t.Fatalf("copy = %v, want %s", err, fault.SourceChanged)
	}
}

// A source directory replaced by a link after the walk listed it is not
// entered: the victim's files are not copied into the destination.
func TestCopyWalkRefusesSwappedSourceDirectory(t *testing.T) {
	for _, openssh := range []bool{false, true} {
		base := raceBase(t)
		victim := filepath.Join(base, "home-alice", ".ssh")
		mkfile(t, filepath.Join(victim, "id_ed25519"), "PRIVATE KEY", 0o600)
		src := filepath.Join(base, "shared", "project")
		mkfile(t, filepath.Join(src, "a_dir", "readme"), "x", 0o644)
		mkfile(t, filepath.Join(src, "z_dir", "own"), "x", 0o644)
		dst := filepath.Join(base, "shared", "backup")
		// The first CLOSE ends the listing of the source root.
		b := raceBackend(t, openssh, firstMatch(func(typ byte, _ string) bool { return typ == pktClose }, func() {
			relink(t, filepath.Join(src, "z_dir"), filepath.Join(base, "parked"), victim)
		}))
		cp := &copier{src: b, dst: b, chunk: 64 << 10, bud: &budget{maxBytes: 1 << 20, maxMembers: 100, maxDepth: 10}}
		err := cp.run(t.Context(), src, dst)
		if _, rerr := os.Stat(filepath.Join(dst, "z_dir", "id_ed25519")); rerr == nil {
			t.Fatalf("openssh=%v: victim's key copied into the destination (copy: %v)", openssh, err)
		}
		if err == nil {
			t.Fatalf("openssh=%v: copy succeeded across a replaced directory", openssh)
		}
	}
}

// A source directory replaced between the walk and the read of its files
// is noticed before a file is opened through the link.
func TestCopyRefusesSourceDirectorySwappedBeforeRead(t *testing.T) {
	base := raceBase(t)
	victim := filepath.Join(base, "home-alice", ".ssh")
	mkfile(t, filepath.Join(victim, "id_ed25519"), "PRIVATE KEY", 0o600)
	src := filepath.Join(base, "shared", "project")
	mkfile(t, filepath.Join(src, "z_dir", "id_ed25519"), "decoy", 0o644)
	dst := filepath.Join(base, "shared", "backup")
	// The MKDIR of the destination directory comes after the walk.
	b := raceBackend(t, true, firstMatch(func(typ byte, p string) bool {
		return typ == 14 && p == filepath.Join(dst, "z_dir")
	}, func() { relink(t, filepath.Join(src, "z_dir"), filepath.Join(base, "parked"), victim) }))
	cp := &copier{src: b, dst: b, chunk: 64 << 10, bud: &budget{maxBytes: 1 << 20, maxMembers: 100, maxDepth: 10}}
	err := cp.run(t.Context(), src, dst)
	if got, _ := os.ReadFile(filepath.Join(dst, "z_dir", "id_ed25519")); string(got) == "PRIVATE KEY" {
		t.Fatal("victim's key copied through the swapped source directory")
	}
	if !fault.Is(err, fault.SourceChanged) {
		t.Fatalf("copy = %v, want %s", err, fault.SourceChanged)
	}
}
