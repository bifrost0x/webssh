package sftp

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
)

func wantCode(t *testing.T, err error, code fault.Code) {
	t.Helper()
	if !fault.Is(err, code) {
		t.Fatalf("got %v, want %s", err, code)
	}
}

func TestHomeStatAndCapabilities(t *testing.T) {
	b, root := newLocal(t, Options{ChmodEnabled: true})
	home, err := b.Home(ctx(t))
	if err != nil || home != root {
		t.Fatalf("home %q %v, want %q", home, err, root)
	}
	c := b.Capabilities()
	if !slices.Contains(c.Replace, files.StrategyAtomic) {
		t.Error("posix-rename not detected")
	}
	if c.Ops.Has(files.CapChmod) {
		t.Error("chmod offered without lsetstat@openssh.com")
	}
	put(t, root+"/f", []byte("abc"), 0o640)
	if err := os.Symlink(root+"/f", root+"/l"); err != nil {
		t.Fatal(err)
	}
	e, err := b.Stat(ctx(t), root+"/l", false)
	if err != nil || !e.IsSymlink {
		t.Fatalf("lstat: %+v %v", e, err)
	}
	e, err = b.Stat(ctx(t), root+"/l", true)
	if err != nil || e.IsSymlink || e.Size != 3 || e.Mode != 0o100640 || e.Owner == nil {
		t.Fatalf("stat: %+v %v", e, err)
	}
	// The path is the server's REALPATH answer; the request server of
	// pkg/sftp only cleans it (the lab test covers OpenSSH, which
	// resolves the link).
	if want := filepath.Clean(root + "/l"); e.Path != want {
		t.Fatalf("stat follow path %q, want %q", e.Path, want)
	}
	_, err = b.Stat(ctx(t), root+"/missing", false)
	wantCode(t, err, fault.FileNotFound)
	wantCode(t, b.Chmod(ctx(t), root+"/f", 0o600), fault.UnsupportedOperation)
}

func TestListingPagesExactly(t *testing.T) {
	b, root := newLocal(t, Options{})
	for i := range 1100 {
		put(t, fmt.Sprintf("%s/d/f%04d", root, i), nil, 0o644)
	}
	l, err := b.OpenListing(ctx(t), root+"/d")
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	for page := 0; ; page++ {
		entries, more, err := l.Next(ctx(t), 500)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.Path != root+"/d/"+e.Name {
				t.Fatalf("path %q", e.Path)
			}
			seen = append(seen, e.Name)
		}
		if want := page < 2; more != want {
			t.Fatalf("page %d: more %v with %d entries", page, more, len(entries))
		}
		if !more {
			break
		}
	}
	if len(seen) != 1100 {
		t.Fatalf("%d entries", len(seen))
	}
	if _, _, err := l.Next(ctx(t), 10); !fault.Is(err, fault.SourceUnavailable) {
		t.Fatalf("listing after the end: %v", err)
	}
	if _, err := b.OpenListing(ctx(t), root+"/nope"); !fault.Is(err, fault.FileNotFound) {
		t.Fatalf("missing directory: %v", err)
	}
}

func TestListingMemberLimit(t *testing.T) {
	b, root := newLocal(t, Options{})
	for i := range files.DefaultMaxMembers + 5 {
		put(t, fmt.Sprintf("%s/big/%d", root, i), nil, 0o644)
	}
	l, err := b.OpenListing(ctx(t), root+"/big")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var err2 error
	for err2 == nil {
		var more bool
		_, more, err2 = l.Next(ctx(t), 1000)
		if !more && err2 == nil {
			t.Fatal("listing over the member limit ended without an error")
		}
	}
	wantCode(t, err2, fault.LimitExceeded)
}

func TestOpenPrefetchAndRanges(t *testing.T) {
	b, root := newLocal(t, Options{ChunkBytes: 32 << 10, Prefetch: 8})
	data := make([]byte, 3<<20+123)
	_, _ = rand.Read(data)
	put(t, root+"/blob", data, 0o644)
	for _, r := range []files.Range{{Offset: 0, Length: -1}, {Offset: 0, Length: 10}, {Offset: 100, Length: 70000},
		{Offset: int64(len(data)) - 5, Length: -1}, {Offset: int64(len(data)) + 9, Length: -1}, {Offset: 1 << 20, Length: 0}} {
		rd, err := b.Open(ctx(t), root+"/blob", r)
		if err != nil {
			t.Fatal(err)
		}
		var got bytes.Buffer
		if _, err := io.Copy(&got, rd); err != nil {
			t.Fatal(err)
		}
		_ = rd.Close()
		want := data[min(r.Offset, int64(len(data))):]
		if r.Length >= 0 && r.Length < int64(len(want)) {
			want = want[:r.Length]
		}
		if !bytes.Equal(got.Bytes(), want) {
			t.Fatalf("range %+v: %d bytes, want %d", r, got.Len(), len(want))
		}
		if rd.Entry().Size != int64(len(data)) {
			t.Fatalf("entry %+v", rd.Entry())
		}
	}
	// Small reads go through the same window.
	rd, err := b.Open(ctx(t), root+"/blob", files.Range{Length: -1})
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(io.LimitReader(struct{ io.Reader }{rd}, 1<<20))
	if err != nil || !bytes.Equal(got, data[:1<<20]) {
		t.Fatalf("small reads: %d %v", len(got), err)
	}
	_ = rd.Close()

	if err := os.Mkdir(root+"/dir", 0o755); err != nil {
		t.Fatal(err)
	}
	_, err = b.Open(ctx(t), root+"/dir", files.Range{Length: -1})
	wantCode(t, err, fault.UnsupportedOperation)
	if err := os.Symlink(root+"/blob", root+"/link"); err != nil {
		t.Fatal(err)
	}
	_, err = b.Open(ctx(t), root+"/link", files.Range{Length: -1})
	wantCode(t, err, fault.UnsupportedOperation)
}

func TestWriteNewReplaceAndExclusive(t *testing.T) {
	b, root := newLocal(t, Options{})
	p := root + "/n.txt"
	res, err := b.Write(ctx(t), p, strings.NewReader("hello"), files.WriteOptions{Exclusive: true, Size: 5})
	if err != nil || res.Size != 5 || res.Revision != files.Revision([]byte("hello")) {
		t.Fatalf("%+v %v", res, err)
	}
	_, err = b.Write(ctx(t), p, strings.NewReader("x"), files.WriteOptions{Exclusive: true, Size: -1})
	wantCode(t, err, fault.FileConflict)

	if err := os.Chmod(p, 0o640); err != nil {
		t.Fatal(err)
	}
	big := bytes.Repeat([]byte("0123456789"), 300000)
	if _, err := b.Write(ctx(t), p, bytes.NewReader(big), files.WriteOptions{Size: int64(len(big))}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	fi, _ := os.Stat(p)
	if !bytes.Equal(got, big) || fi.Mode().Perm() != 0o640 {
		t.Fatalf("replaced %d bytes, mode %v", len(got), fi.Mode())
	}
	noStaging(t, root)
}

func noStaging(t *testing.T, dir string) {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".webssh-") {
			t.Fatalf("staging file left: %s", e.Name())
		}
	}
}

type failingReader struct{ n int }

func (f *failingReader) Read(p []byte) (int, error) {
	if f.n <= 0 {
		return 0, errors.New("upload broke")
	}
	n := min(len(p), f.n)
	f.n -= n
	return n, nil
}

func TestWriteStreamFailuresLeaveTarget(t *testing.T) {
	b, root := newLocal(t, Options{})
	p := root + "/keep"
	put(t, p, []byte("original"), 0o644)
	cases := []struct {
		src  io.Reader
		o    files.WriteOptions
		code fault.Code
	}{
		{strings.NewReader("short"), files.WriteOptions{Size: 10}, fault.SourceChanged},
		{strings.NewReader("much too long"), files.WriteOptions{Size: 3}, fault.SourceChanged},
		{strings.NewReader("over the limit"), files.WriteOptions{Size: -1, MaxBytes: 4}, fault.LimitExceeded},
		{&failingReader{n: 100000}, files.WriteOptions{Size: -1}, fault.SourceChanged},
	}
	for _, c := range cases {
		_, err := b.Write(ctx(t), p, c.src, c.o)
		wantCode(t, err, c.code)
		if got, _ := os.ReadFile(p); string(got) != "original" {
			t.Fatalf("target changed: %q", got)
		}
	}
	noStaging(t, root)
}

func TestWriteEditorRules(t *testing.T) {
	b, root := newLocal(t, Options{})
	p := root + "/conf"
	put(t, p, []byte("a=1\n"), 0o600)
	rev := files.Revision([]byte("a=1\n"))
	_, err := b.Write(ctx(t), p, strings.NewReader("a=2\n"), files.WriteOptions{ExpectedRevision: "0" + rev[1:], Size: -1})
	wantCode(t, err, fault.EditConflict)
	res, err := b.Write(ctx(t), p, strings.NewReader("a=2\n"), files.WriteOptions{ExpectedRevision: rev, Size: -1})
	if err != nil || res.Revision != files.Revision([]byte("a=2\n")) {
		t.Fatal(err)
	}
	_, err = b.Write(ctx(t), root+"/absent", strings.NewReader("x"), files.WriteOptions{ExpectedRevision: rev, Size: -1})
	wantCode(t, err, fault.EditConflict)

	// A link is saved through its target and stays a link.
	put(t, root+"/real/site", []byte("v1"), 0o644)
	if err := os.Symlink(root+"/real/site", root+"/enabled"); err != nil {
		t.Fatal(err)
	}
	_, err = b.Write(ctx(t), root+"/enabled", strings.NewReader("v2"), files.WriteOptions{Size: -1})
	wantCode(t, err, fault.UnsupportedOperation)
	// pkg/sftp's server answers REALPATH without resolving links, so the
	// target is unknown and nothing is saved (the lab test saves through
	// OpenSSH's REALPATH).
	_, err = b.Write(ctx(t), root+"/enabled", strings.NewReader("v2"),
		files.WriteOptions{ExpectedRevision: files.Revision([]byte("v1")), FollowSymlink: true, Size: -1})
	wantCode(t, err, fault.OperationFailed)
	if got, _ := os.ReadFile(root + "/real/site"); string(got) != "v1" {
		t.Fatalf("target %q", got)
	}

	// Special bits are refused before anything is staged.
	put(t, root+"/suid", []byte("x"), 0o644)
	if err := syscall.Chmod(root+"/suid", 0o4755); err != nil {
		t.Fatal(err)
	}
	_, err = b.Write(ctx(t), root+"/suid", strings.NewReader("y"), files.WriteOptions{ExpectedRevision: files.Revision([]byte("x")), Size: -1})
	wantCode(t, err, fault.EditMetadataUnsupported)
	_, err = b.Write(ctx(t), root+"/suid", strings.NewReader("y"), files.WriteOptions{Size: -1})
	wantCode(t, err, fault.AtomicReplaceUnavailable)
	noStaging(t, root)
}

func TestMkdirRenameRemove(t *testing.T) {
	b, root := newLocal(t, Options{})
	if err := b.Mkdir(ctx(t), root+"/a"); err != nil {
		t.Fatal(err)
	}
	wantCode(t, b.Mkdir(ctx(t), root+"/a"), fault.FileConflict)
	put(t, root+"/a/f", []byte("1"), 0o644)
	put(t, root+"/g", []byte("2"), 0o644)
	wantCode(t, b.Rename(ctx(t), root+"/g", root+"/a/f"), fault.FileConflict)
	wantCode(t, b.Rename(ctx(t), root+"/none", root+"/x"), fault.FileNotFound)
	wantCode(t, b.Rename(ctx(t), root+"/a", root+"/a/sub"), fault.InvalidRequest)
	if err := b.Rename(ctx(t), root+"/g", root+"/a/g"); err != nil {
		t.Fatal(err)
	}
	wantCode(t, b.Remove(ctx(t), root+"/a", false, files.Budget{}), fault.FileConflict)

	// A link inside the tree is removed, its target outside stays.
	put(t, root+"/outside/keep", []byte("k"), 0o644)
	if err := os.Symlink(root+"/outside", root+"/a/link"); err != nil {
		t.Fatal(err)
	}
	put(t, root+"/a/deep/er/x", nil, 0o644)
	wantCode(t, b.Remove(ctx(t), root+"/a", true, files.Budget{MaxMembers: 3}), fault.LimitExceeded)
	if err := b.Remove(ctx(t), root+"/a", true, files.Budget{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root + "/a"); !os.IsNotExist(err) {
		t.Fatal("tree left")
	}
	if _, err := os.Stat(root + "/outside/keep"); err != nil {
		t.Fatal("link target removed")
	}
	wantCode(t, b.Remove(ctx(t), "/", true, files.Budget{}), fault.FilePermissionDenied)
}

func TestWalkOrderAndBudget(t *testing.T) {
	b, root := newLocal(t, Options{})
	put(t, root+"/w/a/1", []byte("12"), 0o644)
	put(t, root+"/w/b", []byte("123"), 0o644)
	if err := os.Symlink(root+"/w/a", root+"/w/l"); err != nil {
		t.Fatal(err)
	}
	var paths []string
	err := b.Walk(ctx(t), root+"/w", files.Budget{}, func(e files.Entry) error {
		paths = append(paths, strings.TrimPrefix(e.Path, root))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	pos := func(p string) int { return slices.Index(paths, p) }
	if len(paths) != 5 || pos("/w") != 0 || pos("/w/a") > pos("/w/a/1") || pos("/w/l") < 0 {
		t.Fatalf("walk %v", paths)
	}
	err = b.Walk(ctx(t), root+"/w", files.Budget{MaxBytes: 4}, func(files.Entry) error { return nil })
	wantCode(t, err, fault.LimitExceeded)
	err = b.Walk(ctx(t), root+"/w", files.Budget{MaxDepth: 1}, func(files.Entry) error { return nil })
	wantCode(t, err, fault.LimitExceeded)
	stop := errors.New("stop")
	if err := b.Walk(ctx(t), root+"/w", files.Budget{}, func(files.Entry) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("callback error: %v", err)
	}
}

func TestClosedBackend(t *testing.T) {
	b, root := newLocal(t, Options{})
	put(t, root+"/f", []byte("x"), 0o644)
	rd, err := b.Open(ctx(t), root+"/f", files.Range{Length: -1})
	if err != nil {
		t.Fatal(err)
	}
	_ = b.Close()
	_, err = b.Stat(ctx(t), root+"/f", false)
	wantCode(t, err, fault.SourceUnavailable)
	_, err = b.OpenListing(ctx(t), root)
	wantCode(t, err, fault.SourceUnavailable)
	_, err = b.Write(ctx(t), root+"/g", strings.NewReader(""), files.WriteOptions{Size: 0})
	wantCode(t, err, fault.SourceUnavailable)
	_ = rd.Close()
	if _, err := os.Stat(filepath.Join(root, "g")); !os.IsNotExist(err) {
		t.Fatal("write after close")
	}
}
