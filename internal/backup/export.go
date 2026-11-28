package backup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/bifrost0x/webssh/internal/store"
)

// Scrubber removes from the copy of a portable export (or of a restored
// export) what such a backup must not carry: saved remote passwords and
// SSH private keys (vault.DropRemoteCredentialsTx). Each owner provides
// its own; the composition root lists them.
type Scrubber func(ctx context.Context, tx *store.Tx) error

// ExportRequest describes an online or CLI export (C-BAK-01, C-BAK-07).
type ExportRequest struct {
	// Source is the live database; the export works on a snapshot.
	Source Snapshotter
	// Path is the archive to create; it must not exist.
	Path string
	// Work is a private, empty directory for the snapshot.
	Work string
	// Scrub lists the scrubbers of the portable export.
	Scrub []Scrubber
	// SecretKey is SECRET_KEY; WithoutSecretKey leaves it out of the
	// archive (D-08, --without-secret-key). The material is included
	// unless WithoutMaterial is set: without SECRET_KEY it opens nothing,
	// and with the same SECRET_KEY it lets another host restore the
	// archive. The caller sets WithoutMaterial where the key can be found
	// elsewhere (a 3.3 export of the way back); the archive then verifies
	// with Material and restores only where the material is present.
	SecretKey        []byte
	WithoutSecretKey bool
	WithoutMaterial  bool
	Material         []byte
	KeyID            string
	Release          string
	Now              time.Time
	// Probes verify one sealed record after writing.
	Probes []Probe
	Limits Limits
}

// Export snapshots the live database, removes the remote credentials from
// the copy and rebuilds it, writes the archive (mode 0600) and verifies it
// by reading it back. On error nothing is left at Path.
func Export(ctx context.Context, req ExportRequest) (Verified, error) {
	if req.Source == nil || req.Path == "" || req.Work == "" || len(req.SecretKey) == 0 || len(req.Material) == 0 {
		return Verified{}, errors.New("backup: the export needs a source, a target, SECRET_KEY and the material")
	}
	snap := filepath.Join(req.Work, "snapshot.db")
	defer os.Remove(snap)
	if err := req.Source.Snapshot(ctx, snap); err != nil {
		return Verified{}, fmt.Errorf("backup: snapshot: %w", err)
	}
	if err := scrub(ctx, snap, req.Scrub); err != nil {
		return Verified{}, err
	}
	c := Contents{Database: snap, Material: req.Material, KeyID: req.KeyID, Release: req.Release, Reason: ReasonExport, Now: req.Now}
	if !req.WithoutSecretKey {
		c.SecretKey = req.SecretKey
	}
	opts := VerifyOptions{Secret: req.SecretKey, Probes: req.Probes, Limits: req.Limits}
	if req.WithoutMaterial {
		c.Material, opts.Material = nil, req.Material
	}
	if err := WriteFile(req.Path, c); err != nil {
		return Verified{}, err
	}
	v, err := VerifyWith(ctx, req.Path, opts)
	if err != nil {
		return Verified{}, errors.Join(err, os.Remove(req.Path))
	}
	return v, nil
}

// scrub runs the scrubbers on the database at path in one transaction,
// rebuilds the file and closes it cleanly.
func scrub(ctx context.Context, path string, scrubbers []Scrubber) error {
	db, err := store.Open(ctx, path, store.Options{})
	if err != nil {
		return fmt.Errorf("backup: open the snapshot: %w", err)
	}
	err = db.Write(ctx, func(tx *store.Tx) error {
		for _, s := range scrubbers {
			if err := s(ctx, tx); err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil {
		err = db.Vacuum(ctx)
	}
	if err != nil {
		return errors.Join(fmt.Errorf("backup: remove remote credentials: %w", err), db.Close())
	}
	return db.CloseForActivation(ctx)
}
