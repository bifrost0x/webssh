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

// A tree walk stops at a child whose path is longer than any path a page
// may address (splitPath), not only at an invalid component.
func TestChildNodeRefusesPathBeyondMaxLength(t *testing.T) {
	var parts []string
	for range 16 {
		parts = append(parts, strings.Repeat("ä", 255))
	}
	at := node{parts: parts}
	if _, err := (&Backend{}).childNode(at, &smb2.FileStat{FileName: "x", FileId: 1}); !fault.Is(err, fault.OperationFailed) {
		t.Fatalf("childNode = %v, want %s", err, fault.OperationFailed)
	}
	at.parts = parts[:15]
	if _, err := (&Backend{}).childNode(at, &smb2.FileStat{FileName: "x", FileId: 1}); err != nil {
		t.Fatalf("childNode within the bound = %v", err)
	}
}
