package files_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/files/filestest"
)

func fill(b *filestest.Backend, dir string, n int) {
	for i := range n {
		b.PutFile(fmt.Sprintf("%s/f%04d", dir, i), []byte("x"))
	}
}

func TestListingPagesAndCursorBinding(t *testing.T) {
	t.Parallel()
	f := newFixture(t, files.Options{PageSize: 50})
	fill(f.b, "/d", 120)
	ctx := context.Background()
	c := caller(alice)
	page, err := f.svc.List(ctx, c, f.id, "r1", "/d", "")
	if err != nil || len(page.Entries) != 50 || page.Next == "" {
		t.Fatalf("first page: %d %q %v", len(page.Entries), page.Next, err)
	}
	// The cursor is bound to connection, path and source, and to its offset.
	other := files.Caller{P: alice, Peer: 8}
	for _, try := range []func() error{
		func() error { _, err := f.svc.List(ctx, other, f.id, "r2", "/d", page.Next); return err },
		func() error { _, err := f.svc.List(ctx, c, f.id, "r2", "/e", page.Next); return err },
		func() error {
			_, err := f.svc.List(ctx, c, f.id, "r2", "/d", page.Next[:len(page.Next)-1]+"0")
			return err
		},
		func() error {
			_, err := f.svc.List(ctx, c, f.id, "r2", "/d", strings.Replace(page.Next, ".50.", ".51.", 1))
			return err
		},
	} {
		if err := try(); !fault.Is(err, fault.InvalidRequest) {
			t.Fatalf("forged cursor accepted: %v", err)
		}
	}
	p2, err := f.svc.List(ctx, c, f.id, "r3", "/d", page.Next)
	if err != nil || len(p2.Entries) != 50 || p2.Next == "" || p2.Entries[0].Name != "f0050" {
		t.Fatalf("second page: %v %v", p2, err)
	}
	// The old cursor is spent.
	if _, err := f.svc.List(ctx, c, f.id, "r3", "/d", page.Next); !fault.Is(err, fault.InvalidRequest) {
		t.Fatalf("replayed cursor: %v", err)
	}
	p3, err := f.svc.List(ctx, c, f.id, "r4", "/d", p2.Next)
	if err != nil || len(p3.Entries) != 20 || p3.Next != "" {
		t.Fatalf("last page: %d %q %v", len(p3.Entries), p3.Next, err)
	}
}

func TestListingHomeAndPaths(t *testing.T) {
	t.Parallel()
	f := newFixture(t, files.Options{})
	f.b.PutFile("/a.txt", nil)
	ctx := context.Background()
	for _, dir := range []string{"", ".", "/"} {
		if p, err := f.svc.List(ctx, caller(alice), f.id, "r", dir, ""); err != nil || len(p.Entries) != 1 {
			t.Fatalf("List(%q) = %v, %v", dir, p, err)
		}
	}
	for _, dir := range []string{"rel", "/a/../b", "/a\x00"} {
		if _, err := f.svc.List(ctx, caller(alice), f.id, "r", dir, ""); !fault.Is(err, fault.InvalidRequest) {
			t.Fatalf("List(%q) accepted: %v", dir, err)
		}
	}
}

func TestListingLimits(t *testing.T) {
	t.Parallel()
	f := newFixture(t, files.Options{PageSize: 50, MaxMembers: 120, SnapshotsPerUser: 2, SnapshotsTotal: 3})
	fill(f.b, "/big", 130)
	fill(f.b, "/d", 60)
	ctx := context.Background()
	c := caller(alice)
	first, _ := f.svc.List(ctx, c, f.id, "r", "/big", "")
	second, _ := f.svc.List(ctx, c, f.id, "r", "/big", first.Next)
	if _, err := f.svc.List(ctx, c, f.id, "r", "/big", second.Next); !fault.Is(err, fault.LimitExceeded) {
		t.Fatalf("member limit: %v", err)
	}
	// Per user: the oldest snapshot gives way.
	a, _ := f.svc.List(ctx, c, f.id, "r", "/d", "")
	*f.now = f.now.Add(time.Second)
	b, _ := f.svc.List(ctx, c, f.id, "r", "/d", "")
	*f.now = f.now.Add(time.Second)
	if _, err := f.svc.List(ctx, c, f.id, "r", "/d", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.List(ctx, c, f.id, "r", "/d", a.Next); !fault.Is(err, fault.InvalidRequest) {
		t.Fatalf("oldest snapshot kept: %v", err)
	}
	if _, err := f.svc.List(ctx, c, f.id, "r", "/d", b.Next); err != nil {
		t.Fatalf("newer snapshot evicted: %v", err)
	}
}

func TestListingCancel(t *testing.T) {
	t.Parallel()
	f := newFixture(t, files.Options{PageSize: 50})
	fill(f.b, "/d", 60)
	ctx := context.Background()
	c := caller(alice)
	p, _ := f.svc.List(ctx, c, f.id, "r1", "/d", "")
	f.svc.CancelListing(caller(bob), f.id, p.Next, "")
	f.svc.CancelListing(c, f.id, p.Next, "")
	if _, err := f.svc.List(ctx, c, f.id, "r1", "/d", p.Next); !fault.Is(err, fault.InvalidRequest) {
		t.Fatalf("cancelled cursor continues: %v", err)
	}
	// By request id while the first page is still being read.
	gate := make(chan struct{})
	started := make(chan struct{})
	f.b.Fail = func(op, _ string) error {
		if op == "list" {
			close(started)
			f.b.Fail = nil
			// The backend lock is held; wait without it is impossible, so
			// emulate a slow server by failing once the gate opens.
			<-gate
		}
		return nil
	}
	done := make(chan error, 1)
	go func() { _, err := f.svc.List(ctx, c, f.id, "slow", "/d", ""); done <- err }()
	<-started
	cancelled := make(chan struct{})
	go func() { f.svc.CancelListing(c, f.id, "", "slow"); close(cancelled) }()
	time.Sleep(20 * time.Millisecond)
	close(gate)
	<-cancelled
	if err := <-done; !fault.Is(err, fault.FileCancelled) {
		t.Fatalf("cancelled first page: %v", err)
	}
}

func TestListingsEndWithSourceAndPeer(t *testing.T) {
	t.Parallel()
	f := newFixture(t, files.Options{PageSize: 50})
	fill(f.b, "/d", 60)
	ctx := context.Background()
	c := caller(alice)
	p, _ := f.svc.List(ctx, c, f.id, "r", "/d", "")
	f.svc.PeerClosed(c)
	if _, err := f.svc.List(ctx, c, f.id, "r", "/d", p.Next); err == nil {
		t.Fatal("listing outlived its connection")
	}
}

func TestPreviewDecodesLikeTheEditor(t *testing.T) {
	t.Parallel()
	f := newFixture(t, files.Options{})
	f.b.PutFile("/latin.txt", []byte("Gr\xfc\xdfe\n"))
	f.b.PutFile("/bin", []byte("a\x00b"))
	var log strings.Builder
	for i := range 3000 {
		fmt.Fprintf(&log, "line %d\n", i)
	}
	f.b.PutFile("/log", []byte(log.String()))
	f.b.PutLink("/link", "/latin.txt")
	ctx := context.Background()
	c := caller(alice)
	pv, err := f.svc.Preview(ctx, c, files.PreviewRequest{SourceID: f.id, Path: "/latin.txt"})
	if err != nil || pv.Binary || pv.Text != "Grüße\n" || pv.Encoding != files.EncodingLatin1 {
		t.Fatalf("latin-1 preview: %+v %v", pv, err)
	}
	if pv, _ := f.svc.Preview(ctx, c, files.PreviewRequest{SourceID: f.id, Path: "/bin"}); !pv.Binary {
		t.Fatal("NUL not binary")
	}
	if pv, err := f.svc.Preview(ctx, c, files.PreviewRequest{SourceID: f.id, Path: "/link"}); err != nil || pv.Text != "Grüße\n" {
		t.Fatalf("preview through a link: %+v %v", pv, err)
	}
	n := int64(10)
	pv, err = f.svc.Preview(ctx, c, files.PreviewRequest{SourceID: f.id, Path: "/log", TailLines: &n})
	if err != nil || !pv.Truncated || !strings.HasPrefix(pv.Text, "line 2991\n") || strings.Count(pv.Text, "\n") != 9 {
		t.Fatalf("tail: %q %v", pv.Text, err)
	}
	small := int64(5)
	pv, err = f.svc.Preview(ctx, c, files.PreviewRequest{SourceID: f.id, Path: "/log", MaxBytes: &small})
	if err != nil || pv.Text != "line " || !pv.Truncated || pv.Size != int64(log.Len()) {
		t.Fatalf("bounded preview: %+v %v", pv, err)
	}
	bad := []files.PreviewRequest{
		{SourceID: f.id, Path: "/log", MaxBytes: new(int64)},
		{SourceID: f.id, Path: "/log", TailLines: new(int64)},
		{SourceID: f.id, Path: "/log", TailLines: new(int64(10001))},
		{SourceID: f.id, Path: "/log", Offset: new(int64(-1))},
		{SourceID: f.id, Path: "/log", Offset: new(int64(2 << 30))},
	}
	for _, q := range bad {
		if _, err := f.svc.Preview(ctx, c, q); !fault.Is(err, fault.InvalidRequest) {
			t.Errorf("preview options %+v accepted: %v", q, err)
		}
	}
	if _, err := f.svc.Preview(ctx, c, files.PreviewRequest{SourceID: f.id, Path: "/"}); err == nil {
		t.Error("directory previewed")
	}
}

func TestImagePreviewBounded(t *testing.T) {
	t.Parallel()
	f := newFixture(t, files.Options{MaxEditorBytes: 1 << 20})
	f.b.PutFile("/a.png", []byte("PNG"))
	f.b.PutFile("/big.png", make([]byte, 1<<20+1))
	ctx := context.Background()
	if data, err := f.svc.Image(ctx, caller(alice), f.id, "/a.png"); err != nil || string(data) != "PNG" {
		t.Fatalf("image: %q %v", data, err)
	}
	_, err := f.svc.Image(ctx, caller(alice), f.id, "/big.png")
	wantCode(t, err, fault.FileTooLarge)
	if a := f.audit.last(); a["operation"] != "binary_preview" || a["result"] != "FAILED" || a["filename"] != "big.png" {
		t.Fatalf("audit %v", a)
	}
}
