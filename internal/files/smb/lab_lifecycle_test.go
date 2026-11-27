package smb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/x/wire"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
)

func revisionOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestLabRecoverableSwap(t *testing.T) {
	for _, tg := range labTargets(t) {
		t.Run(tg.name, func(t *testing.T) {
			ctx := t.Context()
			b := connectLab(t, tg, nil)
			dir := labDir(t, b)
			p := dir + "/notes.txt"
			writeFile(t, b, p, "line one\r\n", files.WriteOptions{Exclusive: true})
			_, err := b.Write(ctx, p, strings.NewReader("new"), files.WriteOptions{ExpectedRevision: revisionOf("line one\r\n"), Size: 3})
			wantCode(t, err, fault.SMBRecoverableReplaceNeed)
			if fe, _ := fault.From(err); fe.Details["revision"] != revisionOf("line one\r\n") {
				t.Errorf("details %v", fe.Details)
			}
			_, err = b.Write(ctx, p, strings.NewReader("new"), files.WriteOptions{ExpectedRevision: revisionOf("stale"), Size: 3})
			wantCode(t, err, fault.EditConflict)
			_, err = b.Write(ctx, p, strings.NewReader("new"), files.WriteOptions{Strategy: files.StrategyRecoverableSwap, ExpectedRevision: revisionOf("stale"), Size: 3})
			wantCode(t, err, fault.EditConflict)
			res, err := b.Write(ctx, p, strings.NewReader("line two\r\n"), files.WriteOptions{Strategy: files.StrategyRecoverableSwap,
				ExpectedRevision: revisionOf("line one\r\n"), Size: 10})
			if err != nil || res.Warning != "" || res.Revision != revisionOf("line two\r\n") {
				t.Fatalf("swap %+v %v", res, err)
			}
			if readFile(t, b, p) != "line two\r\n" {
				t.Error("content after swap")
			}
			// A failing source leaves the original and no temporary file.
			_, err = b.Write(ctx, p, &failingReader{n: 5}, files.WriteOptions{Strategy: files.StrategyRecoverableSwap,
				ExpectedRevision: revisionOf("line two\r\n"), Size: -1})
			wantCode(t, err, fault.SourceChanged)
			if readFile(t, b, p) != "line two\r\n" {
				t.Error("content after failed swap")
			}
			if got := names(t, b, dir); !slices.Equal(got, []string{"notes.txt"}) {
				t.Errorf("leftovers %v", got)
			}
		})
	}
}

// TestLabOneSessionServesTwoLanes decides K1 point 32: Python opened two
// sessions per source so that a transfer could not hold up the page. One
// session of the Go library multiplexes requests within its credits: a
// large upload and download run while stats and listings keep answering.
func TestLabOneSessionServesTwoLanes(t *testing.T) {
	for _, tg := range labTargets(t) {
		t.Run(tg.name, func(t *testing.T) {
			ctx := t.Context()
			b := connectLab(t, tg, nil)
			dir := labDir(t, b)
			writeFile(t, b, dir+"/small.txt", "s", files.WriteOptions{Exclusive: true})
			control := func() time.Duration {
				start := time.Now()
				if _, err := b.Stat(ctx, dir+"/small.txt", false); err != nil {
					t.Error(err)
				}
				if got := names(t, b, dir); !slices.Contains(got, "small.txt") {
					t.Errorf("listing %v", got)
				}
				return time.Since(start)
			}
			var idle time.Duration
			for range 5 {
				idle = max(idle, control())
			}
			const size = 96 << 20
			var wg sync.WaitGroup
			done := make(chan struct{})
			wg.Go(func() {
				defer close(done)
				if _, err := b.Write(ctx, dir+"/big.bin", io.LimitReader(zeroReader{}, size), files.WriteOptions{Exclusive: true, Size: size}); err != nil {
					t.Error(err)
					return
				}
				r, err := b.Open(ctx, dir+"/big.bin", files.Range{Length: -1})
				if err != nil {
					t.Error(err)
					return
				}
				n, err := io.Copy(io.Discard, r)
				_ = r.Close()
				if err != nil || n != size {
					t.Errorf("download %d %v", n, err)
				}
			})
			var busy time.Duration
			count := 0
		loop:
			for {
				select {
				case <-done:
					break loop
				default:
					busy = max(busy, control())
					count++
				}
			}
			wg.Wait()
			t.Logf("control round trip idle max %v, during transfer max %v over %d rounds", idle, busy, count)
			if count < 3 || busy > 5*time.Second {
				t.Errorf("control lane held up: %d rounds, max %v", count, busy)
			}
		})
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// TestLabStallMidTransfer: a server that stops answering in the middle of
// a transfer fails it after the I/O idle timeout; the target is not
// changed.
func TestLabStallMidTransfer(t *testing.T) {
	for _, tg := range labTargets(t) {
		t.Run(tg.name, func(t *testing.T) {
			ctx := t.Context()
			direct := connectLab(t, tg, nil)
			dir := labDir(t, direct)
			writeFile(t, direct, dir+"/keep.bin", "original", files.WriteOptions{Exclusive: true})
			writeFile(t, direct, dir+"/down.bin", strings.Repeat("d", 8<<20), files.WriteOptions{Exclusive: true})

			p := newProxy(t, tg.port)
			cfg := labConfig(t, p.port(), p.dial)
			cfg.IOIdleTimeout = 2 * time.Second
			b := connectLab(t, tg, &cfg)

			src := &stallingReader{after: 4 << 20, stall: func() { p.up.Store(true) }}
			start := time.Now()
			_, err := b.Write(ctx, dir+"/keep.bin", io.LimitReader(src, 32<<20), files.WriteOptions{Size: 32 << 20})
			took := time.Since(start)
			wantCode(t, err, fault.FileTimeout)
			if took > 12*time.Second {
				t.Errorf("stalled upload failed after %v", took)
			}
			p.up.Store(false)
			if readFile(t, direct, dir+"/keep.bin") != "original" {
				t.Fatal("a stalled upload changed the target")
			}

			r, err := b.Open(ctx, dir+"/down.bin", files.Range{Length: -1})
			if err != nil {
				t.Skipf("source after the stall: %v", err)
			}
			defer r.Close()
			buf := make([]byte, 1<<20)
			if _, err := io.ReadFull(r, buf); err != nil {
				t.Fatal(err)
			}
			p.down.Store(true)
			start = time.Now()
			_, err = io.Copy(io.Discard, r)
			took = time.Since(start)
			p.down.Store(false)
			wantCode(t, err, fault.FileTimeout)
			if took > 6*time.Second {
				t.Errorf("stalled download failed after %v", took)
			}
			cleanTemps(t, direct, dir)
		})
	}
}

// cleanTemps deletes generated files a stalled session could not remove.
func cleanTemps(t *testing.T, b *Backend, dir string) {
	t.Helper()
	for _, n := range names(t, b, dir) {
		if strings.Contains(n, ".webssh-") {
			t.Logf("left after the stall: %s", n)
			_ = b.Remove(t.Context(), dir+"/"+n, false, files.Budget{})
		}
	}
}

type stallingReader struct {
	after int
	stall func()
	once  sync.Once
}

func (r *stallingReader) Read(p []byte) (int, error) {
	if r.after <= 0 {
		r.once.Do(r.stall)
	}
	n := min(len(p), max(r.after, 1<<16))
	clear(p[:n])
	r.after -= n
	return n, nil
}

// TestLabMutationDeadline: a rename whose answer never comes is
// OUTCOME_UNKNOWN, the session is tainted, and whatever the server did,
// no data is lost.
func TestLabMutationDeadline(t *testing.T) {
	for _, tg := range labTargets(t) {
		t.Run(tg.name, func(t *testing.T) {
			ctx := t.Context()
			direct := connectLab(t, tg, nil)
			dir := labDir(t, direct)
			writeFile(t, direct, dir+"/a.txt", "payload", files.WriteOptions{Exclusive: true})

			p := newProxy(t, tg.port)
			cfg := labConfig(t, p.port(), p.dial)
			cfg.IOIdleTimeout, cfg.MutationTimeout = 2*time.Second, 2*time.Second
			b := connectLab(t, tg, &cfg)
			b.hookRename = func() { p.up.Store(true); p.down.Store(true) }
			start := time.Now()
			err := b.Rename(ctx, dir+"/a.txt", dir+"/b.txt")
			took := time.Since(start)
			wantCode(t, err, fault.OutcomeUnknown)
			if took > 8*time.Second {
				t.Errorf("unknown outcome after %v", took)
			}
			_, err = b.Stat(ctx, dir, false)
			wantCode(t, err, fault.SourceUnavailable)
			p.close()
			got := names(t, direct, dir)
			if !slices.Equal(got, []string{"a.txt"}) && !slices.Equal(got, []string{"b.txt"}) {
				t.Fatalf("after an unknown rename: %v", got)
			}
			if readFile(t, direct, dir+"/"+got[0]) != "payload" {
				t.Fatal("content lost")
			}
		})
	}
}

// TestLabLostReplyReconciled: the reply of a rename is held back past the
// mutation deadline and arrives later; the handle shows the rename done,
// so the result is success. Python compared against the name in
// FileAllInformation, which Windows leaves empty, and reported the
// outcome as uncertain there every time (K1 point 23, fix).
func TestLabLostReplyReconciled(t *testing.T) {
	for _, tg := range labTargets(t) {
		t.Run(tg.name, func(t *testing.T) {
			ctx := t.Context()
			p := newProxy(t, tg.port)
			cfg := labConfig(t, p.port(), p.dial)
			cfg.MutationTimeout = 1500 * time.Millisecond
			b := connectLab(t, tg, &cfg)
			dir := labDir(t, b)
			writeFile(t, b, dir+"/a.txt", "payload", files.WriteOptions{Exclusive: true})
			writeFile(t, b, dir+"/up.txt", "old", files.WriteOptions{Exclusive: true})
			holdReply := func() {
				p.down.Store(true)
				time.AfterFunc(2*time.Second, func() { p.down.Store(false) })
			}
			b.hookRename = holdReply
			start := time.Now()
			if err := b.Rename(ctx, dir+"/a.txt", dir+"/b.txt"); err != nil {
				t.Fatalf("reconciled rename: %v", err)
			}
			if took := time.Since(start); took < cfg.MutationTimeout {
				t.Fatalf("the reply was not held back (%v)", took)
			}
			start = time.Now()
			if _, err := b.Write(ctx, dir+"/up.txt", strings.NewReader("new"), files.WriteOptions{Size: 3}); err != nil {
				t.Fatalf("reconciled replace: %v", err)
			}
			if took := time.Since(start); took < cfg.MutationTimeout || b.dead.Load() {
				t.Fatalf("the reply was not held back (%v) or the session was tainted", took)
			}
			b.hookRename = nil
			if got := names(t, b, dir); !slices.Equal(sorted(got), []string{"b.txt", "up.txt"}) {
				t.Errorf("after reconciled renames: %v", got)
			}
			if readFile(t, b, dir+"/up.txt") != "new" {
				t.Error("replace content")
			}
		})
	}
}

func sorted(s []string) []string { slices.Sort(s); return s }

// TestLabHandleNameSources documents the Python finding: the name inside
// FileAllInformation is empty on Windows Server, while
// FileNormalizedNameInformation carries it on both servers.
func TestLabHandleNameSources(t *testing.T) {
	for _, tg := range labTargets(t) {
		t.Run(tg.name, func(t *testing.T) {
			ctx := t.Context()
			b := connectLab(t, tg, nil)
			dir := labDir(t, b)
			writeFile(t, b, dir+"/Name.txt", "x", files.WriteOptions{Exclusive: true})
			o, err := b.leaf(ctx, []string{dir[1:], "Name.txt"}, nil, accessAttributes, fileOpen, shareAll, kindFile)
			if err != nil {
				t.Fatal(err)
			}
			defer o.release()
			res, err := b.tree.Request().WithFileID(o.file.Fd()).QueryInfo(wire.SMB2_0_INFO_FILE, wire.FileAllInformation, 0, infoBuffer).Do(ctx)
			if err != nil {
				t.Fatal(err)
			}
			qi, _ := res.QueryInfo(0)
			allName := wire.FileAllInformationDecoder(qi.Output()).NameInformation().FileName()
			res.Close()
			t.Logf("FileAllInformation name %q, normalized %q", allName, o.bound)
			if tg.windows && allName != "" {
				t.Errorf("Windows filled the FileAllInformation name: %q", allName)
			}
			if !o.matches([]string{dir[1:], "name.TXT"}) || o.matches([]string{dir[1:], "other.txt"}) {
				t.Errorf("binding %q", o.bound)
			}
		})
	}
}

// TestLabReparsePointsRejected: links on Windows are refused on every
// path and listed as links (needs the administrator for mklink rights).
func TestLabReparsePointsRejected(t *testing.T) {
	for _, tg := range labTargets(t) {
		if !tg.windows {
			continue
		}
		t.Run(tg.name, func(t *testing.T) {
			ctx := t.Context()
			b := connectLab(t, tg, nil)
			dir := labDir(t, b)
			if err := b.Mkdir(ctx, dir+"/real"); err != nil {
				t.Fatal(err)
			}
			writeFile(t, b, dir+"/real/f.txt", "secret", files.WriteOptions{Exclusive: true})
			admin, err := connect(ctx, labConfig(t, tg.port, nil), Target{Host: "127.0.0.1", Share: "C$", Username: tg.adminUser, Password: []byte(tg.adminPassword)})
			if err != nil {
				t.Fatalf("admin connect: %v", err)
			}
			defer admin.Close()
			base := tg.share + `\` + dir[1:]
			if err := admin.tree.Symlink(ctx, `real\f.txt`, base+`\link-file`); err != nil {
				t.Fatalf("file symlink: %v", err)
			}
			if err := admin.tree.Symlink(ctx, `real`, base+`\link-dir`); err != nil {
				t.Fatalf("directory symlink: %v", err)
			}
			_, err = b.Stat(ctx, dir+"/link-file", false)
			wantCode(t, err, fault.SMBReparsePointRejected)
			_, err = b.Open(ctx, dir+"/link-file", files.Range{Length: -1})
			wantCode(t, err, fault.UnsupportedOperation)
			_, err = b.Stat(ctx, dir+"/link-dir/f.txt", false)
			wantCode(t, err, fault.SMBReparsePointRejected)
			_, err = b.Write(ctx, dir+"/link-dir/new.txt", strings.NewReader("x"), files.WriteOptions{Size: 1})
			wantCode(t, err, fault.SMBReparsePointRejected)
			_, err = b.Write(ctx, dir+"/link-file", strings.NewReader("x"), files.WriteOptions{Size: 1})
			wantCode(t, err, fault.SMBReparsePointRejected)
			wantCode(t, b.Remove(ctx, dir, true, files.Budget{}), fault.SMBReparsePointRejected)
			if readFile(t, b, dir+"/real/f.txt") != "secret" {
				t.Fatal("refused recursive delete removed data")
			}
			l, err := b.OpenListing(ctx, dir)
			if err != nil {
				t.Fatal(err)
			}
			page, _, err := l.Next(ctx, 100)
			_ = l.Close()
			if err != nil {
				t.Fatal(err)
			}
			links := 0
			for _, e := range page {
				if e.IsSymlink && !e.IsDir {
					links++
				}
			}
			if links != 2 {
				t.Errorf("listing %+v", page)
			}
			for _, n := range []string{`\link-file`, `\link-dir`} {
				_ = admin.tree.Remove(context.Background(), base+n)
			}
		})
	}
}

var _ = bytes.Equal

// TestLabAncestorsPinned: while an operation holds a path, no other
// session can rename a directory above it (K1 point 17).
func TestLabAncestorsPinned(t *testing.T) {
	for _, tg := range labTargets(t) {
		t.Run(tg.name, func(t *testing.T) {
			ctx := t.Context()
			b := connectLab(t, tg, nil)
			other := connectLab(t, tg, nil)
			dir := labDir(t, b)
			if err := b.Mkdir(ctx, dir+"/sub"); err != nil {
				t.Fatal(err)
			}
			l, err := b.OpenListing(ctx, dir+"/sub")
			if err != nil {
				t.Fatal(err)
			}
			if err := other.Rename(ctx, dir, dir+"-moved"); err == nil {
				_ = l.Close()
				t.Fatal("an ancestor of a held path was renamed")
			}
			_ = l.Close()
			if err := other.Rename(ctx, dir, dir+"-moved"); err != nil {
				t.Fatalf("rename after release: %v", err)
			}
			if err := other.Rename(ctx, dir+"-moved", dir); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestLabTransferCancel: a cancelled upload leaves the target and no
// temporary file; a cancelled download ends promptly; the source stays
// usable (K1 point 26).
func TestLabTransferCancel(t *testing.T) {
	for _, tg := range labTargets(t) {
		t.Run(tg.name, func(t *testing.T) {
			b := connectLab(t, tg, nil)
			dir := labDir(t, b)
			writeFile(t, b, dir+"/keep.bin", "original", files.WriteOptions{Exclusive: true})
			ctx, cancel := context.WithCancel(t.Context())
			src := &stallingReader{after: 8 << 20, stall: cancel}
			_, err := b.Write(ctx, dir+"/keep.bin", io.LimitReader(src, 256<<20), files.WriteOptions{Size: 256 << 20})
			if c := fault.CodeOf(err); c != fault.FileCancelled {
				t.Fatalf("cancelled upload: %v", err)
			}
			if readFile(t, b, dir+"/keep.bin") != "original" {
				t.Fatal("a cancelled upload changed the target")
			}
			if got := names(t, b, dir); !slices.Equal(got, []string{"keep.bin"}) {
				t.Errorf("leftovers %v", got)
			}
			writeFile(t, b, dir+"/big.bin", strings.Repeat("z", 32<<20), files.WriteOptions{Exclusive: true})
			ctx, cancel = context.WithCancel(t.Context())
			r, err := b.Open(ctx, dir+"/big.bin", files.Range{Length: -1})
			if err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 1<<20)
			if _, err := io.ReadFull(r, buf); err != nil {
				t.Fatal(err)
			}
			cancel()
			start := time.Now()
			_, err = io.Copy(io.Discard, r)
			_ = r.Close()
			if fault.CodeOf(err) != fault.FileCancelled || time.Since(start) > 2*time.Second {
				t.Errorf("cancelled download: %v after %v", err, time.Since(start))
			}
			if _, err := b.Stat(t.Context(), dir+"/big.bin", false); err != nil {
				t.Errorf("source after cancel: %v", err)
			}
		})
	}
}
