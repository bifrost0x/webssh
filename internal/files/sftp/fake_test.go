package sftp

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
)

// fakeServer answers requests by a script: handle returns the reply
// packet (type and body after the id) or nil for no reply at all.
type fakeServer struct {
	conn   net.Conn
	mu     sync.Mutex
	seen   []string // request types and extension names in order
	exts   []string // announced extensions; nil: posix-rename and lsetstat
	handle func(typ byte, id uint32, d *decoder) (byte, []byte)
}

func pkt(typ byte, id uint32, body []byte) []byte {
	b := binary.BigEndian.AppendUint32(nil, uint32(5+len(body)))
	b = append(b, typ)
	b = binary.BigEndian.AppendUint32(b, id)
	return append(b, body...)
}

func statusBody(code uint32) []byte {
	return append(append(be32(code), str(nil)...), str(nil)...)
}

func attrsBody(mode uint32) []byte {
	return append(be32(attrPermissions|attrUIDGID), append(append(be32(1000), be32(1000)...), be32(mode)...)...)
}

func newFake(t *testing.T, o Options, handle func(typ byte, id uint32, d *decoder) (byte, []byte), exts ...string) (*Backend, *fakeServer) {
	t.Helper()
	srv, cli := net.Pipe()
	if exts == nil {
		exts = []string{extPosixRename, extLsetstat}
	}
	f := &fakeServer{conn: srv, handle: handle, exts: exts}
	go f.serve()
	c, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	b, err := Open(c, cli, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close(); _ = srv.Close() })
	return b, f
}

func (f *fakeServer) serve() {
	head := make([]byte, 4)
	for {
		if _, err := io.ReadFull(f.conn, head); err != nil {
			return
		}
		body := make([]byte, binary.BigEndian.Uint32(head))
		if _, err := io.ReadFull(f.conn, body); err != nil {
			return
		}
		if body[0] == fxpInit {
			v := be32(3)
			for _, e := range f.exts {
				v = append(v, str([]byte(e))...)
				v = append(v, str([]byte("1"))...)
			}
			out := binary.BigEndian.AppendUint32(nil, uint32(1+len(v)))
			_, _ = f.conn.Write(append(append(out, fxpVersion), v...))
			continue
		}
		id := binary.BigEndian.Uint32(body[1:5])
		d := &decoder{b: body[5:]}
		name := typeName(body[0])
		if body[0] == fxpExtended {
			name = string(d.bytesN(1024))
		}
		if body[0] == fxpExtended && name == extLimits {
			_, _ = f.conn.Write(pkt(fxpStatus, id, statusBody(fxOpUnsupported)))
			continue
		}
		if body[0] == fxpRealpath {
			// Every server answers REALPATH (SFTP v3); the fake resolves
			// nothing and returns the path.
			rep := append(be32(1), str(d.bytesN(1<<20))...)
			rep = append(append(rep, str(nil)...), attrsBody(0)...)
			_, _ = f.conn.Write(pkt(fxpName, id, rep))
			continue
		}
		f.mu.Lock()
		f.seen = append(f.seen, name)
		f.mu.Unlock()
		typ, rep := f.handle(body[0], id, d)
		if rep == nil {
			continue
		}
		_, _ = f.conn.Write(pkt(typ, id, rep))
	}
}

func typeName(t byte) string {
	return map[byte]string{fxpLstat: "lstat", fxpStat: "stat", fxpSetstat: "setstat", fxpRename: "rename",
		fxpMkdir: "mkdir", fxpRemove: "remove", fxpOpen: "open"}[t]
}

func (f *fakeServer) requests() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.seen, ",")
}

func TestStalledServerTimesOut(t *testing.T) {
	b, _ := newFake(t, Options{OperationTimeout: 300 * time.Millisecond},
		func(byte, uint32, *decoder) (byte, []byte) { return 0, nil })
	start := time.Now()
	_, err := b.Stat(context.Background(), "/x", false)
	wantCode(t, err, fault.FileTimeout)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %v", d)
	}
	select {
	case <-b.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("stalled channel not closed")
	}
	_, err = b.Stat(context.Background(), "/x", false)
	wantCode(t, err, fault.SourceUnavailable)
}

func TestCancelReturnsPromptly(t *testing.T) {
	b, _ := newFake(t, Options{}, func(byte, uint32, *decoder) (byte, []byte) { return 0, nil })
	c, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := b.Stat(c, "/x", false)
	if !fault.Is(err, fault.FileTimeout) && !fault.Is(err, fault.FileCancelled) {
		t.Fatal(err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancel ignored")
	}
}

func TestOversizedRepliesCloseTheChannel(t *testing.T) {
	b, _ := newFake(t, Options{}, func(_ byte, _ uint32, _ *decoder) (byte, []byte) {
		return fxpAttrs, ext(17, 1)
	})
	_, err := b.Stat(context.Background(), "/x", false)
	wantCode(t, err, fault.OperationFailed)
	<-b.Done()

	b2, f := newFake(t, Options{MaxPacketBytes: MinMaxPacketBytes}, func(byte, uint32, *decoder) (byte, []byte) { return 0, nil })
	go func() {
		// A packet header over the limit, sent unasked.
		_, _ = f.conn.Write(binary.BigEndian.AppendUint32(nil, MinMaxPacketBytes+1))
	}()
	select {
	case <-b2.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("oversized packet accepted")
	}
}

func TestLostRenameReplyIsUnknown(t *testing.T) {
	var b *Backend
	b, f := newFake(t, Options{}, func(typ byte, id uint32, d *decoder) (byte, []byte) {
		p := string(d.bytesN(4096))
		switch {
		case typ == fxpLstat && p == "/from":
			return fxpAttrs, attrsBody(0o100644)
		case typ == fxpLstat:
			return fxpStatus, statusBody(fxNoSuchFile)
		case typ == fxpRename:
			go func() { time.Sleep(20 * time.Millisecond); b.r.fail(errClosed) }()
			return 0, nil
		}
		return fxpStatus, statusBody(fxFailure)
	})
	err := b.Rename(context.Background(), "/from", "/to")
	wantCode(t, err, fault.OutcomeUnknown)
	if got := f.requests(); got != "lstat,lstat,rename" {
		t.Fatalf("requests %s", got)
	}
}

func TestChmodNeverFollowsLinks(t *testing.T) {
	mode := uint32(0o100644)
	var mu sync.Mutex
	b, f := newFake(t, Options{ChmodEnabled: true}, func(typ byte, id uint32, d *decoder) (byte, []byte) {
		mu.Lock()
		defer mu.Unlock()
		p := string(d.bytesN(4096))
		switch {
		case typ == fxpLstat && p == "/link":
			return fxpAttrs, attrsBody(0o120777)
		case typ == fxpLstat:
			return fxpAttrs, attrsBody(mode)
		case typ == fxpExtended: // lsetstat@openssh.com; p is its path
			a := d.attrs(testLimits)
			mode = mode&^0o7777 | a.mode
			return fxpStatus, statusBody(fxOK)
		}
		return fxpStatus, statusBody(fxOpUnsupported)
	})
	if !b.Capabilities().Ops.Has(files.CapChmod) {
		t.Fatal("chmod not offered with lsetstat@openssh.com and the switch on")
	}
	if err := b.Chmod(context.Background(), "/file", 0o600); err != nil {
		t.Fatal(err)
	}
	wantCode(t, b.Chmod(context.Background(), "/link", 0o600), fault.UnsupportedOperation)
	if got := f.requests(); got != "lstat,lsetstat@openssh.com,lstat,lstat" {
		t.Fatalf("requests %s", got)
	}
	mu.Lock()
	mode = 0o104755
	mu.Unlock()
	wantCode(t, b.Chmod(context.Background(), "/file", 0o700), fault.UnsupportedOperation)
}

func TestChmodModeMismatch(t *testing.T) {
	b, _ := newFake(t, Options{ChmodEnabled: true}, func(typ byte, _ uint32, d *decoder) (byte, []byte) {
		if typ == fxpLstat {
			return fxpAttrs, attrsBody(0o100644)
		}
		return fxpStatus, statusBody(fxOK)
	})
	wantCode(t, b.Chmod(context.Background(), "/file", 0o600), fault.ModeMismatch)
}

// Without posix-rename@openssh.com nothing is replaced (Python rule: no
// delete window); new files are still written.
func TestNoPosixRenameRefusesReplace(t *testing.T) {
	b, f := newFake(t, Options{ChmodEnabled: true}, func(typ byte, _ uint32, d *decoder) (byte, []byte) {
		if typ == fxpLstat {
			return fxpAttrs, attrsBody(0o100644)
		}
		return fxpStatus, statusBody(fxOpUnsupported)
	}, "fsync@openssh.com")
	c := b.Capabilities()
	if len(c.Replace) != 0 || c.Ops.Has(files.CapChmod) {
		t.Fatalf("capabilities %+v", c)
	}
	_, err := b.Write(context.Background(), "/existing", strings.NewReader("x"), files.WriteOptions{Size: 1})
	wantCode(t, err, fault.AtomicReplaceUnavailable)
	_, err = b.Write(context.Background(), "/existing", strings.NewReader("x"),
		files.WriteOptions{Size: 1, ExpectedRevision: files.Revision(nil)})
	wantCode(t, err, fault.AtomicReplaceUnavailable)
	if got := f.requests(); got != "lstat,lstat" {
		t.Fatalf("requests %s: something was staged", got)
	}
}

// A server that answers OPEN with STATUS OK sends no handle; pkg/sftp
// returns neither a file nor an error for it.
func TestOpenWithoutHandleFails(t *testing.T) {
	b, _ := newFake(t, Options{}, func(typ byte, _ uint32, _ *decoder) (byte, []byte) {
		if typ == fxpLstat {
			return fxpAttrs, attrsBody(0o100644)
		}
		return fxpStatus, statusBody(fxOK)
	})
	if _, err := b.Open(context.Background(), "/file", files.Range{Length: -1}); err == nil {
		t.Fatal("Open succeeded without a handle")
	}
}
