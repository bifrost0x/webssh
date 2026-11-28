package automation

import (
	"context"
	"encoding/binary"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pkgsftp "github.com/pkg/sftp"

	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/files/sftp"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
)

// raceSource is cmd/webssh's permBackend over an SFTP backend.
type raceSource struct{ b *sftp.Backend }

func (p raceSource) Lstat(ctx context.Context, path string) (PermEntry, error) {
	e, err := p.b.Stat(ctx, path, false)
	if err != nil {
		return PermEntry{}, err
	}
	out := PermEntry{Mode: e.Mode, Size: e.Size, ModTime: e.ModTime}
	if e.Owner != nil {
		uid, gid := e.Owner.UID, e.Owner.GID
		out.UID, out.GID = &uid, &gid
	}
	return out, nil
}

func (p raceSource) Children(ctx context.Context, dir string, fn func(string) error) error {
	l, err := p.b.OpenListing(ctx, dir)
	if err != nil {
		return err
	}
	defer l.Close()
	for {
		entries, more, err := l.Next(ctx, 512)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if err := fn(e.Name); err != nil {
				return err
			}
		}
		if !more {
			return nil
		}
	}
}

func (p raceSource) Chmod(ctx context.Context, path string, perm uint32, want PermEntry) error {
	e := files.Entry{Mode: want.Mode, Size: want.Size, ModTime: want.ModTime}
	if want.UID != nil && want.GID != nil {
		e.Owner = &files.Owner{UID: *want.UID, GID: *want.GID}
	}
	return p.b.ChmodExpect(ctx, path, fs.FileMode(perm)&fs.ModePerm, e)
}

type raceSources struct{ b *sftp.Backend }

func (s raceSources) Hold(context.Context, principal.Principal, string) (PermSource, any, func(), error) {
	return raceSource{s.b}, s.b, func() {}, nil
}
func (s raceSources) Clean(p string) (string, error) { return files.CleanTarget(p) }

func readPacket(r io.Reader) ([]byte, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, err
	}
	p := make([]byte, 4+binary.BigEndian.Uint32(head))
	copy(p, head)
	_, err := io.ReadFull(r, p[4:])
	return p, err
}

func packetString(b []byte) (string, []byte) {
	n := binary.BigEndian.Uint32(b)
	return string(b[4 : 4+n]), b[4+n:]
}

// chmodProxy sits in front of pkg/sftp's server, announces
// lsetstat@openssh.com and serves it as SETSTAT (the same for a path whose
// last component is not a link). hook sees the request type ("lsetstat",
// "open", "lstat") and path right before the server does.
func chmodProxy(t *testing.T, hook func(op, path string)) net.Conn {
	cli, pc := net.Pipe()
	ps, srv := net.Pipe()
	server, err := pkgsftp.NewServer(srv)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve() }()
	go func() {
		for {
			p, err := readPacket(pc)
			if err != nil {
				_ = ps.Close()
				return
			}
			switch p[4] {
			case 200: // SSH_FXP_EXTENDED
				if name, rest := packetString(p[9:]); name == "lsetstat@openssh.com" {
					path, _ := packetString(rest)
					hook("lsetstat", path)
					body := append(append([]byte{9}, p[5:9]...), rest...) // SSH_FXP_SETSTAT
					p = append(binary.BigEndian.AppendUint32(nil, uint32(len(body))), body...)
				}
			case 3: // SSH_FXP_OPEN
				path, _ := packetString(p[9:])
				hook("open", path)
			case 7: // SSH_FXP_LSTAT
				path, _ := packetString(p[9:])
				hook("lstat", path)
			}
			if _, err := ps.Write(p); err != nil {
				return
			}
		}
	}()
	go func() {
		for {
			p, err := readPacket(ps)
			if err != nil {
				_ = pc.Close()
				return
			}
			if p[4] == 2 { // SSH_FXP_VERSION
				body := append([]byte{}, p[4:]...)
				for _, s := range []string{"lsetstat@openssh.com", "1"} {
					body = binary.BigEndian.AppendUint32(body, uint32(len(s)))
					body = append(body, s...)
				}
				p = append(binary.BigEndian.AppendUint32(nil, uint32(len(body))), body...)
			}
			if _, err := pc.Write(p); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { _ = cli.Close(); _ = srv.Close() })
	return cli
}

// A local user with write access below the tree replaces a directory by a
// link to /etc right before the job changes a file in it. The change must
// not reach the file of the same name in the link target.
func TestPermissionJobDoesNotFollowSwappedParent(t *testing.T) {
	cases := []struct {
		name string
		// at reports whether the swap happens at this request; lstats
		// counts the LSTATs of the file since the apply began.
		at func(op string, lstats int) bool
	}{
		// The request that changes the mode: lsetstat by path, or the
		// OPEN of the handle the change is made on.
		{"before the change", func(op string, _ int) bool { return op == "lsetstat" || op == "open" }},
		// The lstat of the backend, after the job compared its own
		// (the first two are the preflight and the job's check).
		{"before the backend's check", func(op string, lstats int) bool { return op == "lstat" && lstats == 3 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The job freezes every ancestor up to "/"; a busy /tmp would
			// change under it, so the tree lives beside the test.
			dir, err := os.MkdirTemp(".", ".permrace-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			root, err := filepath.Abs(dir)
			if err == nil {
				root, err = filepath.EvalSymlinks(root)
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range []string{root + "/srv/up/d", root + "/etc"} {
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			for p, data := range map[string]string{root + "/srv/up/d/shadow": "attacker", root + "/etc/shadow": "root:secret"} {
				if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(p, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			target := root + "/srv/up/d/shadow"
			var armed atomic.Bool
			var mu sync.Mutex
			lstats, swapped := 0, false
			cli := chmodProxy(t, func(op, p string) {
				if !armed.Load() || p != target {
					return
				}
				mu.Lock()
				defer mu.Unlock()
				if op == "lstat" {
					lstats++
				}
				if !swapped && tc.at(op, lstats) {
					swapped = true
					_ = os.Rename(root+"/srv/up/d", root+"/srv/up/d.real")
					_ = os.Symlink(root+"/etc", root+"/srv/up/d")
				}
			})
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			b, err := sftp.Open(ctx, cli, sftp.Options{ChmodEnabled: true})
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			j, err := NewPermissionJobs(PermOptions{Sources: raceSources{b}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = j.Shutdown(context.Background()) }()
			c := PermCaller{P: principaltest.User(5), Peer: 1}
			const sid = "sftp-quick:hx"
			st, err := j.Prepare(ctx, c, PermRequest{SourceID: sid, Paths: []string{root + "/srv/up"}, Recursive: true, FileMode: "644", DirMode: "755"})
			if err != nil {
				t.Fatal(err)
			}
			id := jsonMember(st, "job_id")
			wait := func(states ...string) string {
				for range 500 {
					st, err := j.Get(ctx, c, sid, id)
					if err != nil {
						t.Fatal(err)
					}
					for _, w := range states {
						if s := jsonMember(st, "state"); s == w {
							return s
						}
					}
					time.Sleep(10 * time.Millisecond)
				}
				t.Fatal("job did not finish")
				return ""
			}
			if s := wait(permReady, permFailed); s != permReady {
				t.Fatalf("scan: %s", s)
			}
			armed.Store(true)
			if _, err := j.Apply(ctx, c, sid, id); err != nil {
				t.Fatal(err)
			}
			if s := wait(permCompleted, permFailed, permCancelled); s != permFailed {
				t.Errorf("job state %s, want %s", s, permFailed)
			}
			if !swapped {
				t.Fatal("the swap never ran")
			}
			fi, err := os.Stat(root + "/etc/shadow")
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != 0o600 {
				t.Errorf("the job changed /etc/shadow outside the tree to %o", fi.Mode().Perm())
			}
		})
	}
}
