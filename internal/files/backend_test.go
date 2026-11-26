package files_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/files/filestest"
)

// openForEdit is the editor's read path as FS1 builds it on the contract:
// open, decode with the one rule, remember the revision.
func openForEdit(ctx context.Context, b files.Backend, p string, max int64) (string, string, error) {
	r, err := b.Open(ctx, p, files.Range{Length: -1})
	if err != nil {
		return "", "", err
	}
	defer r.Close()
	if r.Entry().Size > max {
		return "", "", fault.New(fault.FileTooLarge, "")
	}
	raw, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return "", "", err
	}
	text, _, binary := files.Decode(raw)
	if binary {
		return "", "", fault.New(fault.FileBinary, "")
	}
	return files.EditorText(text), files.Revision(raw), nil
}

func TestEditorFlowOnTheContract(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	b := filestest.New()
	b.PutFile("/etc/app.conf", []byte("a=1\r\nb=2\r\n"))
	text, rev, err := openForEdit(ctx, b, "/etc/app.conf", 1<<20)
	if err != nil || text != "a=1\nb=2\n" {
		t.Fatalf("openForEdit = %q, %v", text, err)
	}
	// Someone else saves first: the stale revision is refused.
	if _, err := b.Write(ctx, "/etc/app.conf", strings.NewReader("x"), files.WriteOptions{Size: -1}); err != nil {
		t.Fatal(err)
	}
	_, err = b.Write(ctx, "/etc/app.conf", strings.NewReader("a=3\r\n"), files.WriteOptions{ExpectedRevision: rev, Size: -1})
	if !fault.Is(err, fault.EditConflict) {
		t.Fatalf("stale save = %v, want EDIT_CONFLICT", err)
	}
	got, _ := b.File("/etc/app.conf")
	if string(got) != "x" {
		t.Fatalf("stale save changed the file to %q", got)
	}
	b.PutFile("/bin.dat", []byte("ab\x00cd"))
	if _, _, err := openForEdit(ctx, b, "/bin.dat", 1<<20); !fault.Is(err, fault.FileBinary) {
		t.Fatalf("binary = %v", err)
	}
	if _, _, err := openForEdit(ctx, b, "/etc/app.conf", 0); !fault.Is(err, fault.FileTooLarge) {
		t.Fatalf("too large = %v", err)
	}
}

func TestFakeBackendSemantics(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	b := filestest.New()
	b.PutFile("/d/a.txt", []byte("hello"))
	b.PutLink("/d/link", "/d/a.txt")

	if _, err := b.Write(ctx, "/d/a.txt", strings.NewReader("x"), files.WriteOptions{Exclusive: true, Size: -1}); !fault.Is(err, fault.FileConflict) {
		t.Errorf("exclusive write = %v", err)
	}
	if _, err := b.Write(ctx, "/d/link", strings.NewReader("x"), files.WriteOptions{Size: -1}); !fault.Is(err, fault.UnsupportedOperation) {
		t.Errorf("write through a link without FollowSymlink = %v", err)
	}
	if res, err := b.Write(ctx, "/d/link", strings.NewReader("new"), files.WriteOptions{FollowSymlink: true, Size: 3}); err != nil || res.Revision != files.Revision([]byte("new")) {
		t.Errorf("write through a link = %+v, %v", res, err)
	}
	if e, _ := b.Stat(ctx, "/d/link", false); !e.IsSymlink {
		t.Error("the link was replaced")
	}
	if _, err := b.Write(ctx, "/d/a.txt", strings.NewReader("four"), files.WriteOptions{Size: 3}); !fault.Is(err, fault.SourceChanged) {
		t.Errorf("short source = %v", err)
	}
	if _, err := b.Write(ctx, "/d/a.txt", strings.NewReader("four"), files.WriteOptions{Size: -1, MaxBytes: 3}); !fault.Is(err, fault.LimitExceeded) {
		t.Errorf("over MaxBytes = %v", err)
	}
	if _, err := b.Write(ctx, "/d/a.txt", strings.NewReader("x"), files.WriteOptions{Size: -1, Strategy: files.StrategyRecoverableSwap}); !fault.Is(err, fault.AtomicReplaceUnavailable) {
		t.Errorf("unsupported strategy = %v", err)
	}
	if err := b.Rename(ctx, "/d/a.txt", "/d/link"); !fault.Is(err, fault.FileConflict) {
		t.Errorf("rename over an existing name = %v", err)
	}
	if err := b.Rename(ctx, "/d", "/d/sub"); err == nil {
		t.Error("moved a directory into itself")
	}
	if err := b.Remove(ctx, "/d", false, files.Budget{}); !fault.Is(err, fault.FileConflict) {
		t.Errorf("non-recursive remove of a full directory = %v", err)
	}
	if err := b.Remove(ctx, "/d", true, files.Budget{MaxMembers: 2}); !fault.Is(err, fault.LimitExceeded) {
		t.Errorf("remove over budget = %v", err)
	}
	if err := b.Chmod(ctx, "/d/a.txt", 0o600); !fault.Is(err, fault.UnsupportedOperation) {
		t.Errorf("chmod without capability = %v", err)
	}
	if err := b.Remove(ctx, "/d", true, files.Budget{}); err != nil {
		t.Errorf("recursive remove = %v", err)
	}
	if _, err := b.Stat(ctx, "/d/a.txt", false); !fault.Is(err, fault.FileNotFound) {
		t.Errorf("stat after remove = %v", err)
	}

	boom := errors.New("lost reply")
	b.Fail = func(op, _ string) error {
		if op == "mkdir" {
			return fault.Wrap(fault.OutcomeUnknown, boom, "")
		}
		return nil
	}
	if err := b.Mkdir(ctx, "/x"); !fault.Is(err, fault.OutcomeUnknown) || !errors.Is(err, boom) {
		t.Errorf("injected failure = %v", err)
	}
	b.Fail = nil
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Stat(ctx, "/", false); !fault.Is(err, fault.SourceUnavailable) {
		t.Errorf("after Close = %v", err)
	}
}

func TestListingPages(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	b := filestest.New()
	for _, n := range []string{"c", "a", "b"} {
		b.PutFile("/dir/"+n, bytes.Repeat([]byte(n), 3))
	}
	l, err := b.OpenListing(ctx, "/dir")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var names []string
	for more := true; more; {
		var page []files.Entry
		page, more, err = l.Next(ctx, 2)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range page {
			names = append(names, e.Name)
		}
	}
	if strings.Join(names, ",") != "a,b,c" {
		t.Errorf("listing = %v", names)
	}
}
