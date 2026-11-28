package sftp

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	pkgsftp "github.com/pkg/sftp"
)

// hookChan sits between the backend and an SFTP server. Before a request
// reaches the server it calls hook with the packet type and the first
// path of the request, so a test can change the file system at an exact
// point of an operation: the deterministic form of a lost race.
type hookChan struct {
	io.Reader
	w    io.Writer
	cl   io.Closer
	hook func(typ byte, p string)
	mu   sync.Mutex
	buf  []byte
}

func (h *hookChan) Write(p []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.buf = append(h.buf, p...)
	for len(h.buf) >= 4 {
		n := int(binary.BigEndian.Uint32(h.buf))
		if len(h.buf) < 4+n {
			break
		}
		pkt := h.buf[:4+n]
		if body := pkt[4:]; len(body) >= 9 && body[0] != fxpInit {
			if l := int(binary.BigEndian.Uint32(body[5:9])); 9+l <= len(body) {
				h.hook(body[0], string(body[9:9+l]))
			}
		}
		if _, err := h.w.Write(pkt); err != nil {
			return 0, err
		}
		h.buf = h.buf[4+n:]
	}
	return len(p), nil
}

func (h *hookChan) Close() error { return h.cl.Close() }

// openSSHServer runs the OpenSSH sftp-server on stdin and stdout, the
// program sshd starts for the subsystem. Unlike pkg/sftp's server it
// resolves links in REALPATH, as every real server does.
func openSSHServer(t *testing.T) (io.Reader, io.WriteCloser) {
	t.Helper()
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
	t.Cleanup(func() {
		_ = in.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return out, in
}

// hooked opens a backend whose requests pass hook. With openssh the
// server is OpenSSH, otherwise pkg/sftp's server.
func hooked(t *testing.T, openssh bool, hook func(typ byte, p string)) *Backend {
	t.Helper()
	var ch *hookChan
	if openssh {
		r, w := openSSHServer(t)
		ch = &hookChan{Reader: r, w: w, cl: w, hook: hook}
	} else {
		srvSide, cli := net.Pipe()
		srv, err := pkgsftp.NewServer(srvSide)
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = srv.Serve() }()
		t.Cleanup(func() { _ = srv.Close() })
		ch = &hookChan{Reader: cli, w: cli, cl: cli, hook: hook}
	}
	c, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	b, err := Open(c, ch, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

// swapToLink replaces dir by a link to target, keeping the old directory
// under park: what a local user with write access to the parent does.
func swapToLink(t *testing.T, dir, park, target string) {
	t.Helper()
	if err := os.Rename(dir, park); err != nil {
		t.Error(err)
		return
	}
	if err := os.Symlink(target, dir); err != nil {
		t.Error(err)
	}
}
