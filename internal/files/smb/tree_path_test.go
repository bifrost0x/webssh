package smb

import (
	"strings"
	"testing"

	"github.com/hirochachacha/go-smb2/v2"

	"github.com/bifrost0x/webssh/internal/fault"
)

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
