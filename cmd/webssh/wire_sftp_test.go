package main

import (
	"context"
	"slices"
	"testing"

	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/files/filestest"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// A terminal session's file_source is the descriptor before the first use
// until the caller's browser session opened the source; from then on it
// is the open source with its real capabilities. Another browser session
// of the same user still gets the descriptor before the first use.
func TestTerminalFileSource(t *testing.T) {
	reg := files.NewRegistry(files.RegistryOptions{})
	b := filestest.New()
	b.SetCapabilities(files.Capabilities{Ops: files.CapAll | files.CapChmod})
	reg.RegisterKind(files.SourceSFTPSession, func(_ context.Context, _ principal.Principal, _ string) (files.Descriptor, files.Backend, error) {
		return files.Descriptor{Kind: files.KindSFTP, Label: "build", Endpoint: "lab.example:22", Protocol: "SFTP",
			Security: files.Security{HostKeyVerified: true}}, b, nil
	})
	describe := terminalFiles{}.fileSource(reg)
	p := principal.Principal{UserID: 1, SessionID: "login-a"}
	info := protocol.SessionInfo{SessionID: "0f7c", Host: "lab.example", Port: 22, Username: "ops", DisplayName: "build"}

	before := describe(p, info)
	if before == nil || before.SourceID != "sftp-session:0f7c" || before.Label != "build" || slices.Contains(before.Capabilities, "chmod") {
		t.Fatalf("before first use %+v", before)
	}
	_, release, err := reg.Resolve(t.Context(), p, "sftp-session:0f7c", files.CapList)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if open := describe(p, info); open == nil || open.SourceID != "sftp-session:0f7c" || !slices.Contains(open.Capabilities, "chmod") {
		t.Fatalf("open source %+v", open)
	}
	other := describe(principal.Principal{UserID: 1, SessionID: "login-b"}, info)
	if other == nil || slices.Contains(other.Capabilities, "chmod") {
		t.Fatalf("other browser session %+v", other)
	}
	if bad := describe(p, protocol.SessionInfo{SessionID: "not a handle"}); bad != nil {
		t.Fatalf("invalid handle %+v", bad)
	}
}
