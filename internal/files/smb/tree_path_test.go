package smb

import (
	"strings"
	"testing"

	smb2 "github.com/hirochachacha/go-smb2/v2"

	"github.com/bifrost0x/webssh/internal/fault"
)

// A tree walk refuses an entry whose share path exceeds maxPathLength, as
// SMBPath.parse does, before it keeps the path: a deep share cannot make
// one walk hold hundreds of MiB of path strings.
func TestChildNodeBoundsPathLength(t *testing.T) {
	t.Parallel()
	var b Backend
	name := strings.Repeat("d", maxComponent)
	at := node{}
	for len(joinPath(at.parts))+1+len(name) <= maxPathLength {
		n, err := b.childNode(at, &smb2.FileStat{FileName: name, FileId: 7})
		if err != nil {
			t.Fatalf("depth %d: %v", len(at.parts), err)
		}
		at = n
	}
	if _, err := b.childNode(at, &smb2.FileStat{FileName: name, FileId: 7}); !fault.Is(err, fault.OperationFailed) {
		t.Fatalf("path of %d characters accepted: %v", len(joinPath(at.parts))+1+len(name), err)
	}
}
