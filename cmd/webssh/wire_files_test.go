package main

import (
	"context"
	"testing"

	"github.com/bifrost0x/webssh/internal/config"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/files/filestest"
	"github.com/bifrost0x/webssh/internal/principal"
)

// The file area is wired with the configured limits and closes the file
// sources of a revoked session.
func TestSystemWiresFiles(t *testing.T) {
	sys, _ := openTestSystem(t, map[string]string{"MAX_EDITOR_FILE_SIZE": "1048576"})
	if sys.files == nil || sys.fileSources == nil || sys.files.MaxEditorBytes() != 1<<20 {
		t.Fatal("file area not wired")
	}
	p := principal.Principal{UserID: 1, SessionID: "s1"}
	id, err := sys.fileSources.Add(p, files.SourceSFTPQuick, files.Descriptor{Kind: files.KindSFTP}, filestest.New())
	if err != nil {
		t.Fatal(err)
	}
	sys.sessions.Publish([]principal.Revocation{{SessionID: "s1", UserID: 1, Reason: principal.ReasonLogout}})
	if _, _, err := sys.fileSources.Resolve(context.Background(), p, id, files.CapList); !fault.Is(err, fault.SourceUnavailable) {
		t.Fatalf("source survives the revocation: %v", err)
	}
}

func TestRealtimeQueueBytes(t *testing.T) {
	for _, c := range []struct{ editor, want int64 }{
		{5 << 20, 41 << 20}, {1 << 10, 8 << 20}, {1 << 40, 1 << 30},
	} {
		if got := realtimeQueueBytes(config.Files{MaxEditorBytes: c.editor}); got != c.want {
			t.Errorf("editor %d: %d, want %d", c.editor, got, c.want)
		}
	}
}
