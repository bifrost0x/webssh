//go:build lab

package sftp_test

import (
	"context"
	json "encoding/json/v2"
	"testing"

	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/files/sftp"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/quota"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/realtime/protocol/protocoltest"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

type labConnector struct {
	target client.Target
	ix     client.Interaction
}

func (c labConnector) Target(context.Context, int64, protocol.OpenTarget) (client.Target, error) {
	return c.target, nil
}

func (c labConnector) Interaction(protocol.Peer, string) client.Interaction { return c.ix }

// Quick SFTP through the realtime type: the source takes one quota slot,
// lists the home directory and frees the slot when it is closed.
func TestLabQuickOpenThroughTheArea(t *testing.T) {
	r := newRig(t, sftp.Options{})
	q, err := quota.New(quota.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	reg := files.NewRegistry(files.RegistryOptions{Quotas: q})
	t.Cleanup(reg.Shutdown)
	a := &sftp.Area{Quick: r.quick, Registry: reg, Connector: labConnector{r.modern(t), r.ix}, Sessions: noSessions{}}
	alice := principal.Principal{UserID: 1, SessionID: "s1"}
	ctx := principal.With(t.Context(), alice)
	peer := protocoltest.NewPeer(t, alice)
	raw, perr := protocoltest.Call(ctx, routes(a)[protocol.TypeFilesQuickOpen], peer, map[string]any{"client_request_id": "quick_1", "auth_type": "password"})
	if perr != nil {
		t.Fatalf("quick open: %+v", perr)
	}
	var opened protocol.FilesQuickOpened
	if err := json.Unmarshal(raw, &opened); err != nil {
		t.Fatal(err)
	}
	if opened.ClientRequestID != "quick_1" || opened.FileSource.SourceID != "sftp-quick:"+opened.ConnectionID ||
		opened.FileSource.Kind != "sftp" || !opened.FileSource.Security["host_key_verified"] {
		t.Fatalf("opened %+v", opened)
	}
	if u := q.Usage()[quota.QuickConnection]; u.Used != 1 {
		t.Fatalf("quota after open %+v", u)
	}
	b, release, err := reg.Resolve(ctx, alice, opened.FileSource.SourceID, files.CapList)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Home(ctx); err != nil {
		t.Fatal(err)
	}
	release()
	if _, perr := protocoltest.Call(ctx, routes(a)[protocol.TypeFilesQuickClose], peer, map[string]any{"connection_id": opened.ConnectionID}); perr != nil {
		t.Fatalf("quick close: %+v", perr)
	}
	if u := q.Usage()[quota.QuickConnection]; u.Used != 0 {
		t.Fatalf("quota after close %+v", u)
	}
}
