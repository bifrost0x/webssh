package smb2

import (
	"testing"

	"github.com/hirochachacha/go-smb2/v2/x/protocol"
	"github.com/stretchr/testify/require"
)

// TestReaddirMalformedEntriesGO20265051 pins the fix for GO-2026-5051, an
// out-of-bounds read in ReadDir that the vulnerability database records for
// the v1 module path only, so govulncheck cannot report it for this module.
// A server-supplied NextEntryOffset past the buffer or a FileNameLength that
// does not fit must fail the listing with an InvalidResponseError, never
// panic.
func TestReaddirMalformedEntriesGO20265051(t *testing.T) {
	t.Parallel()
	entry := func(mutate func([]byte)) []byte {
		buf := encodeFileIdBothDirectoryInformation("file.txt")
		mutate(buf)
		return buf
	}
	tests := []struct {
		name string
		buf  []byte
	}{
		{"next entry past the buffer", entry(func(b []byte) { le.PutUint32(b[0:4], uint32(len(b)+8)) })},
		{"maximum next entry offset", entry(func(b []byte) { le.PutUint32(b[0:4], ^uint32(0)) })},
		{"file name longer than the buffer", entry(func(b []byte) { le.PutUint32(b[60:64], uint32(len(b))) })},
		{"maximum file name length", entry(func(b []byte) { le.PutUint32(b[60:64], ^uint32(0)) })},
		{"truncated entry", encodeFileIdBothDirectoryInformation("file.txt")[:103]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.NotPanics(t, func() {
				_, err := parseReaddir(t, tt.buf)
				var invalid *protocol.InvalidResponseError
				require.ErrorAs(t, err, &invalid)
			})
		})
	}
}
