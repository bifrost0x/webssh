package backup

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

// ErrUnknownFormat reports an archive that is neither a Go backup (tar)
// nor a Python backup (zip).
var ErrUnknownFormat = fmt.Errorf("%w: the archive is neither a WebSSH Go backup nor a Python backup", ErrInvalid)

// Format families an archive can belong to; Python archives are told
// apart (v1, v2) by their manifest, which internal/migrate/legacy reads.
const (
	familyGo     = "go"
	familyPython = "python"
)

// detect tells a tar archive (Go format) from a zip archive (Python
// format) by their magic bytes. It reads nothing else.
func detect(r io.ReaderAt, size int64) (string, error) {
	var head [262]byte
	n, err := r.ReadAt(head[:], 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("backup: read the archive: %w", err)
	}
	b := head[:n]
	switch {
	case bytes.HasPrefix(b, []byte("PK\x03\x04")), bytes.HasPrefix(b, []byte("PK\x05\x06")):
		return familyPython, nil
	case size >= 512 && n >= 262 && bytes.Equal(b[257:262], []byte("ustar")):
		return familyGo, nil
	}
	return "", ErrUnknownFormat
}
