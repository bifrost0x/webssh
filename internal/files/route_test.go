package files_test

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/files/filestest"
)

// routedBackend is a backend on a known network path.
type routedBackend struct {
	*filestest.Backend
	peer   netip.Addr
	onward []string
	known  bool
}

func (b routedBackend) Route() (netip.Addr, []string, bool) { return b.peer, b.onward, b.known }

// Turning the tailnet block on closes the Quick SFTP sources on a route
// the block now refuses at once, held or not, and frees their quota
// (close_connections_where). Sources on an allowed route, sources without
// a known route (Tailscale SSH), terminal session sources and SMB sources
// (the rule is about SSH) stay open.
func TestCloseRestrictedRoutes(t *testing.T) {
	t.Parallel()
	f := newFixture(t, files.Options{}) // f.id: a backend without a route
	f.q.max = 10
	ctx := context.Background()
	node, lan := netip.MustParseAddr("100.100.100.10"), netip.MustParseAddr("192.168.1.10")
	add := func(kind files.SourceKind, b routedBackend) string {
		t.Helper()
		id, err := f.reg.Add(alice, kind, files.Descriptor{Kind: files.KindSFTP}, b)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	sftp := add(files.SourceSFTPQuick, routedBackend{filestest.New(), node, nil, true})
	smb := add(files.SourceSMBQuick, routedBackend{filestest.New(), node, nil, true})
	jumped := add(files.SourceSFTPQuick, routedBackend{filestest.New(), lan, []string{node.String()}, true})
	allowed := add(files.SourceSFTPQuick, routedBackend{filestest.New(), lan, nil, true})
	tailscale := add(files.SourceSFTPQuick, routedBackend{filestest.New(), node, nil, false})
	session := add(files.SourceSFTPSession, routedBackend{filestest.New(), node, nil, true})
	before := f.q.count(1)

	held, release, err := f.reg.Resolve(ctx, alice, sftp, files.CapRead)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	var asked int
	n := f.reg.CloseRestrictedRoutes(func(peer netip.Addr, onward []string) bool {
		asked++
		return peer == node || slices.Contains(onward, node.String())
	})
	if n != 2 || asked != 3 {
		t.Fatalf("closed %d, asked %d", n, asked)
	}
	if _, err := held.Home(ctx); !fault.Is(err, fault.SourceUnavailable) {
		t.Fatalf("held source still open: %v", err)
	}
	for _, id := range []string{sftp, jumped} {
		if _, err := f.svc.Home(ctx, caller(alice), id); !fault.Is(err, fault.SourceUnavailable) {
			t.Fatalf("%s resolves after the close: %v", id, err)
		}
	}
	for _, id := range []string{f.id, allowed, tailscale, session, smb} {
		if _, err := f.svc.Home(ctx, caller(alice), id); err != nil {
			t.Fatalf("%s was closed: %v", id, err)
		}
	}
	if got := f.q.count(1); got != before-2 {
		t.Fatalf("quota %d, want %d", got, before-2)
	}
	if f.reg.CloseRestrictedRoutes(func(netip.Addr, []string) bool { return false }) != 0 {
		t.Fatal("an allowed source was closed")
	}
}
