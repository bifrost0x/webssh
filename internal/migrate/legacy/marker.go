package legacy

import (
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// Marker is logs/.webssh-go/migrated: the identity of the Go database a
// migration activated (section 2.2). It is a hint, not a validity
// criterion: a missing Go directory with the marker present is S1a.
type Marker struct {
	DatabaseID string `json:"database_id"`
	MigratedAt string `json:"migrated_at"`
}

// maxMarkerBytes bounds the marker read; it holds two short strings.
const maxMarkerBytes = 4096

// readMarker returns the marker, or nil when there is none. A marker that
// is not a regular file or does not parse still counts as present.
func readMarker(l layout) (*Marker, error) {
	info, err := os.Lstat(l.marker)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("legacy: inspect %s: %w", l.marker, err)
	}
	unknown := &Marker{DatabaseID: "unknown", MigratedAt: "unknown"}
	if !info.Mode().IsRegular() {
		return unknown, nil
	}
	f, err := os.Open(l.marker) // #nosec G304 -- the Go-owned marker
	if err != nil {
		return unknown, nil
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxMarkerBytes))
	var m Marker
	if err != nil || json.Unmarshal(data, &m) != nil || m.DatabaseID == "" {
		return unknown, nil
	}
	return &m, nil
}

// writeMarker writes the marker atomically: a temporary file in the state
// directory, fsynced, renamed over the marker, and the directory fsynced.
func writeMarker(l layout, m Marker) error {
	if err := l.ensureStateDir(); err != nil {
		return err
	}
	data, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("legacy: encode the marker: %w", err)
	}
	tmp := filepath.Join(l.stateDir, markerTmpName)
	if err := os.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("legacy: remove %s: %w", tmp, err)
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- a Go-owned file
	if err != nil {
		return fmt.Errorf("legacy: write the marker: %w", err)
	}
	_, werr := f.Write(data)
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		return errors.Join(fmt.Errorf("legacy: write the marker: %w", err), os.Remove(tmp))
	}
	if err := os.Rename(tmp, l.marker); err != nil {
		return errors.Join(fmt.Errorf("legacy: write the marker: %w", err), os.Remove(tmp))
	}
	return syncDir(l.stateDir)
}
