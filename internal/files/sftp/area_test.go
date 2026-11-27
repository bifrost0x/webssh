package sftp_test

import (
	"context"
	"io"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/files/sftp"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/realtime/protocol/protocoltest"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// connector resolves every request to target, or fails with err.
type connector struct {
	target client.Target
	err    error
}

func (c connector) Target(context.Context, int64, protocol.OpenTarget) (client.Target, error) {
	return c.target, c.err
}

func (connector) Interaction(protocol.Peer, string) client.Interaction { return nil }

type noSessions struct{}

func (noSessions) Session(context.Context, principal.Principal, string) (sftp.Session, error) {
	return sftp.Session{}, fault.New(fault.SourceUnavailable, "")
}

// refusingQuota allows nothing.
type refusingQuota struct{}

func (refusingQuota) Reserve(context.Context, string, int64, int64) (func(), error) {
	return nil, fault.New(fault.Busy, "quick_connection quota exceeded (per_user limit 3)")
}

func routes(a *sftp.Area) map[string]protocol.Route {
	out := map[string]protocol.Route{}
	for _, r := range a.Routes() {
		out[r.Type] = r
	}
	return out
}

func TestAreaRefusalsAndReasons(t *testing.T) {
	alice := principal.Principal{UserID: 1, SessionID: "s1", Username: "alice"}
	peer := protocoltest.NewPeer(t, alice)
	ctx := principal.With(t.Context(), alice)
	call := func(a *sftp.Area, typ string, payload any) (string, *protocol.Error) {
		raw, perr := protocoltest.Call(ctx, routes(a)[typ], peer, payload)
		return string(raw), perr
	}
	plain := client.Target{Hop: client.Hop{Host: "h.example", Port: 22, User: "u"}}

	// The target checks of terminal.open answer first.
	a := &sftp.Area{Quick: &sftp.Quick{}, Registry: files.NewRegistry(files.RegistryOptions{}),
		Connector: connector{err: fault.New(fault.InvalidValue, "Host is required.")}, Sessions: noSessions{}}
	if _, perr := call(a, protocol.TypeFilesQuickOpen, map[string]any{"auth_type": "password"}); perr == nil || perr.Code != fault.InvalidValue {
		t.Fatalf("target refusal: %+v", perr)
	}
	// Quick SFTP over the gateway or Tailscale SSH is not built (C-GW-02).
	a.Connector = connector{target: client.Target{Hop: plain.Hop, Variant: &client.Variant{}}}
	if _, perr := call(a, protocol.TypeFilesQuickOpen, map[string]any{"host": "h"}); perr == nil || perr.Code != fault.NotAvailableInPreview {
		t.Fatalf("variant: %+v", perr)
	}
	// The quota is taken before dialling, with the text of the Python pool.
	a.Connector = connector{target: plain}
	a.Registry = files.NewRegistry(files.RegistryOptions{Quotas: refusingQuota{}})
	if _, perr := call(a, protocol.TypeFilesQuickOpen, map[string]any{"host": "h"}); perr == nil || perr.Code != fault.Busy ||
		perr.Message != "Maximum number of quick connections reached" {
		t.Fatalf("quota: %+v", perr)
	}
	// Closing someone else's or an unknown connection reveals nothing.
	for _, id := range []string{"", "nope", "a/b"} {
		if _, perr := call(a, protocol.TypeFilesQuickClose, map[string]any{"connection_id": id}); perr == nil {
			t.Fatalf("close %q succeeded", id)
		}
	}
	// The probe needs both identifiers and an owned session.
	if _, perr := call(a, protocol.TypeFilesSessionProbe, map[string]any{"session_id": "s"}); perr == nil || perr.Code != fault.InvalidRequest {
		t.Fatalf("probe without request id: %+v", perr)
	}
	if _, perr := call(a, protocol.TypeFilesSessionProbe, map[string]any{"session_id": "s", "request_id": "r"}); perr == nil || perr.Code != fault.SourceUnavailable {
		t.Fatalf("probe of a foreign session: %+v", perr)
	}
	for payload, want := range map[string]string{"": `{"directory":null,"reason":"unavailable"}`, "s": `{"directory":null,"reason":"unavailable"}`} {
		raw, perr := call(a, protocol.TypeFilesSessionDirectory, map[string]any{"session_id": payload})
		if perr != nil || raw != want {
			t.Fatalf("directory %q: %s %+v", payload, raw, perr)
		}
	}
}

// answeringExec answers the directory probe with a ready shell in /srv.
type answeringExec struct{}

func (answeringExec) Exec(_ context.Context, _ string, _ io.Reader, stdout, _ io.Writer) (int, error) {
	_, err := io.WriteString(stdout, "webssh-directory\x0042\x001\x00bash\x00/srv\x00")
	return 0, err
}

type idleSessions struct{ idle *atomic.Bool }

func (s idleSessions) Session(context.Context, principal.Principal, string) (sftp.Session, error) {
	return sftp.Session{Exec: answeringExec{}, InputIdle: s.idle.Load}, nil
}

// input_idle is the terminal's prompt state read after the probe; a
// session that reports none is never idle.
func TestDirectoryReportsTheTerminalPromptState(t *testing.T) {
	alice := principal.Principal{UserID: 1, SessionID: "s1", Username: "alice"}
	peer := protocoltest.NewPeer(t, alice)
	ctx := principal.With(t.Context(), alice)
	idle := &atomic.Bool{}
	a := &sftp.Area{Sessions: idleSessions{idle}}
	for _, want := range []bool{false, true} {
		idle.Store(want)
		raw, perr := protocoltest.Call(ctx, routes(a)[protocol.TypeFilesSessionDirectory], peer, map[string]any{"session_id": "s"})
		if perr != nil || !strings.Contains(string(raw), `"path":"/srv"`) ||
			!strings.Contains(string(raw), `"input_idle":`+strconv.FormatBool(want)) {
			t.Fatalf("idle %v: %s %+v", want, raw, perr)
		}
	}
}
