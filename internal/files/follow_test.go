package files_test

import (
	"context"
	"io"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/files/filestest"
)

// Reads follow links (Python read through sites-enabled/* and the like);
// Backend.Open itself does not, and changes never touch the target.
func TestReadsFollowLinksChangesDoNot(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b := filestest.New()
	b.PutFile("/etc/nginx/sites-available/web", []byte("server {}\n"))
	b.PutLink("/etc/nginx/sites-enabled/web", "/etc/nginx/sites-available/web")
	b.PutLink("/etc/nginx/dirlink", "/etc/nginx/sites-available")
	b.PutLink("/etc/nginx/dangling", "/nowhere")

	if _, err := b.Open(ctx, "/etc/nginx/sites-enabled/web", files.Range{Length: -1}); !fault.Is(err, fault.UnsupportedOperation) {
		t.Fatalf("Backend.Open followed a link: %v", err)
	}
	rd, opened, err := files.OpenFollow(ctx, b, "/etc/nginx/sites-enabled/web", files.Range{Length: -1})
	if err != nil || opened != "/etc/nginx/sites-available/web" {
		t.Fatalf("OpenFollow: %q %v", opened, err)
	}
	data, _ := io.ReadAll(rd)
	_ = rd.Close()
	if string(data) != "server {}\n" {
		t.Fatalf("read %q", data)
	}
	for _, p := range []string{"/etc/nginx/dirlink", "/etc/nginx/dangling", "/etc/nginx/sites-available"} {
		if _, _, err := files.OpenFollow(ctx, b, p, files.Range{Length: -1}); err == nil {
			t.Errorf("OpenFollow(%s) opened", p)
		}
	}

	f := newFixture(t, files.Options{})
	f.b.PutFile("/t/target", []byte("keep"))
	f.b.PutLink("/t/link", "/t/target")
	f.b.PutLink("/t/link2", "/t/target")
	c := caller(alice)
	if doc, err := f.svc.OpenEdit(ctx, c, f.id, "/t/link"); err != nil || doc.Text != "keep" {
		t.Fatalf("editor through a link: %+v %v", doc, err)
	}
	if err := f.svc.Rename(ctx, c, f.id, "/t/link2", "/t/moved"); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Delete(ctx, c, f.id, "/t/link"); err != nil {
		t.Fatal(err)
	}
	if got, ok := f.b.File("/t/target"); !ok || string(got) != "keep" {
		t.Fatal("a change of the link reached its target")
	}
	if e, err := f.b.Stat(ctx, "/t/moved", false); err != nil || !e.IsSymlink {
		t.Fatalf("rename moved the target, not the link: %+v %v", e, err)
	}
}
