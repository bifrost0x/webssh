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
		MaxTransferMembers: 10000, MaxPreviewBytes: 512000, MaxPreviewTailLines: 10000, MaxSupportedFileSize: 1 << 30, MaxPathBytes: 4096,
		SFTP: SFTP{MaxPacketBytes: 1 << 20, MaxHandleBytes: 16 << 10, MaxNameBytes: 4096, MaxMetadataBytes: 4 << 20,
			OperationTimeout: 30 * time.Second},
		Transfers: Transfers{MaxUpload: 100 << 20, MaxDownload: 100 << 20, MaxArchive: 500 << 20},
	}
	if c.Files != want {
		t.Fatalf("defaults %+v", c.Files)
	}
	c, _ = mustLoad(t, map[string]string{
		"MAX_EDITOR_FILE_SIZE": "1048576", "EDITOR_SAVE_BYTES_PER_MINUTE": "2097152", "REMOTE_LISTING_PAGE_SIZE": "50",
		"REMOTE_LISTING_SNAPSHOT_TTL_SECONDS": "10", "MAX_PREVIEW_SIZE": "1000",
		"SFTP_MAX_PACKET_BYTES": "65536", "SFTP_OPERATION_TIMEOUT": "5", "REMOTE_FILENAME_MAX_BYTES": "255",
	})
	if s := c.Files.SFTP; s.MaxPacketBytes != 64<<10 || s.OperationTimeout != 5*time.Second || s.MaxNameBytes != 255 {
		t.Fatalf("configured SFTP %+v", s)
	}
	if c.Files.MaxEditorBytes != 1<<20 || c.Files.EditorBytesPerMinute != 2<<20 || c.Files.ListingPageSize != 50 ||
		c.Files.SnapshotTTL != 10*time.Second || c.Files.MaxPreviewBytes != 1000 {
		t.Fatalf("configured %+v", c.Files)
	}
	c, _ = mustLoad(t, map[string]string{"MAX_UPLOAD_SIZE": "10", "MAX_DOWNLOAD_SIZE": "-1", "MAX_ZIP_DOWNLOAD_SIZE": "30"})
	if c.Files.Transfers != (Transfers{MaxUpload: 10, MaxDownload: -1, MaxArchive: 30}) {
		t.Fatalf("configured transfers %+v", c.Files.Transfers)
	}
	if loadErr(t, map[string]string{"MAX_UPLOAD_SIZE": "0"}) == nil {
		t.Fatal("upload limit 0 accepted")
	}
	if loadErr(t, map[string]string{"REMOTE_LISTING_PAGE_SIZE": "10"}) == nil {
		t.Fatal("page size below 50 accepted")
	}
}
