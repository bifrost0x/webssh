package legacy

import (
	"context"

	"github.com/bifrost0x/webssh/internal/store"
)

// SourceWatch re-checks the legacy source while Go runs (migration
// specification, section 5.7): a Python process that still writes to the
// same DATA_DIR changes the source after activation. The composition root
// calls Changed on its own clock (every 60 seconds) and switches to
// maintenance on a change. A SourceWatch is not safe for concurrent use.
type SourceWatch struct {
	dataDir   string
	digest    string
	files     []FileStat
	scannedAt int64
}

// NewSourceWatch reads the migration record of db. It returns nil without
// an error when there is no record: a Go-native installation has no
// legacy source to watch.
func NewSourceWatch(ctx context.Context, db *store.DB, dataDir string) (*SourceWatch, error) {
	var rec *Record
	err := db.Read(ctx, func(tx *store.Tx) (err error) {
		rec, err = readRecord(ctx, tx)
		return err
	})
	if err != nil || rec == nil {
		return nil, err
	}
	return &SourceWatch{dataDir: dataDir, digest: rec.SourceDigest, files: rec.Listing, scannedAt: rec.ScannedAt}, nil
}

// Changed scans the legacy source with the stat fast path of section 5.3
// and reports whether its digest differs from the recorded one. A link or
// special file counts as a change. An error means the source could not be
// read; callers treat it as a change (fail closed).
func (w *SourceWatch) Changed() (bool, error) {
	l, err := scanSource(w.dataDir, w.files, w.scannedAt)
	if err != nil {
		return true, err
	}
	if l.Digest() != w.digest {
		return true, nil
	}
	// The next scan can reuse the hashes of this one.
	w.files, w.scannedAt = l.Files, l.ScannedAt
	return false, nil
}
