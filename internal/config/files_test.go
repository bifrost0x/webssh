package config

import (
	"testing"
	"time"
)

func TestFileLimits(t *testing.T) {
	c, _ := mustLoad(t, nil)
	want := Files{
		MaxEditorBytes: 5 << 20, EditorBytesPerMinute: 20 << 20, ControlBytesPerMin: 2 << 20,
		ListingPageSize: 500, SnapshotTTL: time.Minute, SnapshotsTotal: 8, SnapshotsPerUser: 4,
		MaxTransferMembers: 10000, MaxPreviewBytes: 512000, MaxPreviewTailLines: 10000, MaxSupportedFileSize: 1 << 30,
	}
	if c.Files != want {
		t.Fatalf("defaults %+v", c.Files)
	}
	c, _ = mustLoad(t, map[string]string{
		"MAX_EDITOR_FILE_SIZE": "1048576", "EDITOR_SAVE_BYTES_PER_MINUTE": "2097152", "REMOTE_LISTING_PAGE_SIZE": "50",
		"REMOTE_LISTING_SNAPSHOT_TTL_SECONDS": "10", "MAX_PREVIEW_SIZE": "1000",
	})
	if c.Files.MaxEditorBytes != 1<<20 || c.Files.EditorBytesPerMinute != 2<<20 || c.Files.ListingPageSize != 50 ||
		c.Files.SnapshotTTL != 10*time.Second || c.Files.MaxPreviewBytes != 1000 {
		t.Fatalf("configured %+v", c.Files)
	}
	if loadErr(t, map[string]string{"REMOTE_LISTING_PAGE_SIZE": "10"}) == nil {
		t.Fatal("page size below 50 accepted")
	}
}
