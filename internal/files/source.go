package files

import (
	"strings"

	"github.com/bifrost0x/webssh/internal/fault"
)

// maxHandle is the length limit of the handle part of a source id
// ([A-Za-z0-9][A-Za-z0-9_-]{0,127} in app/file_sources.py).
const maxHandle = 128

var errSourceID = fault.New(fault.SourceUnavailable, "")

// ParseSourceID splits "<kind>:<handle>". An unknown kind or a malformed
// handle fails with fault.SourceUnavailable, the answer the Python release
// gave for every source it could not resolve.
func ParseSourceID(id string) (SourceKind, string, error) {
	kind, handle, ok := strings.Cut(id, ":")
	if !ok || !validHandle(handle) {
		return "", "", errSourceID
	}
	switch k := SourceKind(kind); k {
	case SourceSFTPSession, SourceSFTPQuick, SourceSMBQuick:
		return k, handle, nil
	}
	return "", "", errSourceID
}

// FormatSourceID builds a source id; the handle must be valid.
func FormatSourceID(kind SourceKind, handle string) (string, error) {
	id := string(kind) + ":" + handle
	if _, _, err := ParseSourceID(id); err != nil {
		return "", err
	}
	return id, nil
}

func validHandle(h string) bool {
	if h == "" || len(h) > maxHandle {
		return false
	}
	for i := range len(h) {
		c := h[i]
		alnum := 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
		if !alnum && (i == 0 || c != '_' && c != '-') {
			return false
		}
	}
	return true
}
