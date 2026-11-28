package files_test

import (
	"context"
	"io"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/files/filestest"
)

// noFollow refuses FollowSymlink like the SMB backend, which cannot save
// through a link.
type noFollow struct{ *filestest.Backend }

func (b noFollow) Write(ctx context.Context, p string, src io.Reader, o files.WriteOptions) (files.WriteResult, error) {
	if o.FollowSymlink {
		return files.WriteResult{}, fault.New(fault.SMBReparsePointRejected, "")
	}
	return b.Backend.Write(ctx, p, src, o)
}

// The editor asks to save through a link only where the source offers
// it (SymlinkTargets); an SMB share must not refuse every save.
func TestSaveFollowsLinksOnlyWhereOffered(t *testing.T) {
	t.Parallel()
	f := newFixture(t, files.Options{})
	b := noFollow{filestest.New()}
	b.SetCapabilities(files.Capabilities{Ops: files.CapAll, Replace: []files.Strategy{files.StrategyAtomic}})
	b.PutFile("/share/a.txt", []byte("alt\n"))
	id, err := f.reg.Add(alice, files.SourceSFTPQuick, files.Descriptor{Kind: files.KindSFTP, Label: "a@h", Endpoint: "h:445", Protocol: "SMB", Ephemeral: true}, b)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	c := caller(alice)
	doc, err := f.svc.OpenEdit(ctx, c, id, "/share/a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Save(ctx, c, files.SaveRequest{SourceID: id, Path: "/share/a.txt", Content: "neu\n",
		Encoding: string(doc.Encoding), Newline: string(doc.Newline), ExpectedRevision: doc.Revision}); err != nil {
		t.Fatal(err)
	}
	if got, _ := b.File("/share/a.txt"); string(got) != "neu\n" {
		t.Fatalf("saved %q", got)
	}
}
