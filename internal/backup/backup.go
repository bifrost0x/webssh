// Package backup writes and verifies Go backups (decisions D-03, D-08).
//
// This first version covers what `webssh legacy purge` requires before it
// removes legacy data (migration specification, section 5.9): a single
// tar archive with a versioned manifest, the cleanly closed Go database,
// SECRET_KEY and the keyring material, verified by reading it back. The
// online backup, restore and secret rotation follow in B7 and read this
// format.
//
// Archive layout (format "webssh-go-backup", version 1):
//
//	manifest.json             first member: format, version, key id, files
//	data/go/webssh.db         the Go database
//	data/secret_key           SECRET_KEY (only with includes_secret_key)
//	data/go/keyring-material  the keyring material (likewise)
//
// The members below data/ are named by their place in DATA_DIR, so that a
// manual restore copies them back into the stopped installation.
package backup

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Format identifies the archive format.
const (
	FormatName    = "webssh-go-backup"
	FormatVersion = 1
)

// Member names.
const (
	ManifestName = "manifest.json"
	DatabaseName = "data/go/webssh.db"
	SecretName   = "data/secret_key"
	MaterialName = "data/go/keyring-material"
)

// maxManifest bounds the manifest a reader accepts.
const maxManifest = 1 << 20

// Manifest describes an archive.
type Manifest struct {
	Format            string `json:"format"`
	Version           int    `json:"version"`
	CreatedAt         string `json:"created_at"`
	Release           string `json:"release"`
	Reason            string `json:"reason"`
	IncludesSecretKey bool   `json:"includes_secret_key"`
	// KeyID is the key identifier of the keyring the database's sealed
	// records belong to.
	KeyID string `json:"key_id"`
	Files []File `json:"files"`
}

// File is one member of the archive below data/.
type File struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Contents is what Write puts into an archive. Database must be closed
// cleanly (no -wal or -shm file belongs to it) and must not change while
// Write runs; the caller holds the Go lock.
type Contents struct {
	Database  string
	SecretKey []byte
	Material  []byte
	KeyID     string
	Release   string
	Reason    string
	Now       time.Time
}

type source struct {
	name string
	path string // a file, or
	data []byte // in-memory content
}

// Write creates dir/webssh-backup-<UTC>.tar with mode 0600, syncs it and
// dir, and returns its path. A partly written archive is removed.
func Write(dir string, c Contents) (string, error) {
	if c.Database == "" || c.KeyID == "" || len(c.SecretKey) == 0 || len(c.Material) == 0 {
		return "", errors.New("backup: database, key id, secret and material are required")
	}
	sources := []source{{name: DatabaseName, path: c.Database}, {name: SecretName, data: c.SecretKey},
		{name: MaterialName, data: c.Material}}
	m := Manifest{Format: FormatName, Version: FormatVersion, CreatedAt: c.Now.UTC().Format(time.RFC3339Nano),
		Release: c.Release, Reason: c.Reason, IncludesSecretKey: true, KeyID: c.KeyID}
	for _, s := range sources {
		f, err := s.describe()
		if err != nil {
			return "", err
		}
		m.Files = append(m.Files, f)
	}
	path := filepath.Join(dir, "webssh-backup-"+c.Now.UTC().Format("20060102T150405.000000000Z")+".tar")
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- the backup target the operator chose
	if err != nil {
		return "", fmt.Errorf("backup: create %s: %w", path, err)
	}
	err = writeArchive(out, m, sources, c.Now)
	err = errors.Join(err, out.Sync(), out.Close())
	if err == nil {
		err = syncDir(dir)
	}
	if err != nil {
		return "", errors.Join(fmt.Errorf("backup: write %s: %w", path, err), os.Remove(path))
	}
	return path, nil
}

func (s source) open() (io.ReadCloser, int64, error) {
	if s.path == "" {
		return io.NopCloser(bytesReader(s.data)), int64(len(s.data)), nil
	}
	f, err := os.Open(s.path) // #nosec G304 -- the Go database
	if err != nil {
		return nil, 0, err
	}
	info, err := f.Stat()
	if err != nil {
		return nil, 0, errors.Join(err, f.Close())
	}
	if !info.Mode().IsRegular() {
		return nil, 0, errors.Join(fmt.Errorf("backup: %s is not a regular file", s.path), f.Close())
	}
	return f, info.Size(), nil
}

func (s source) describe() (File, error) {
	r, size, err := s.open()
	if err != nil {
		return File{}, fmt.Errorf("backup: read %s: %w", s.name, err)
	}
	defer r.Close()
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil || n != size {
		return File{}, errors.Join(fmt.Errorf("backup: read %s", s.name), err)
	}
	return File{Name: s.name, Size: size, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

func writeArchive(w io.Writer, m Manifest, sources []source, now time.Time) error {
	manifest, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(w)
	hdr := func(name string, size int64) *tar.Header {
		return &tar.Header{Typeflag: tar.TypeReg, Name: name, Size: size, Mode: 0o600, ModTime: now.UTC(), Format: tar.FormatPAX}
	}
	if err := tw.WriteHeader(hdr(ManifestName, int64(len(manifest)))); err != nil {
		return err
	}
	if _, err := tw.Write(manifest); err != nil {
		return err
	}
	for i, s := range sources {
		if err := copyMember(tw, hdr(s.name, m.Files[i].Size), s, m.Files[i]); err != nil {
			return err
		}
	}
	return tw.Close()
}

// copyMember writes one member and checks that the content still has the
// hash the manifest names.
func copyMember(tw *tar.Writer, h *tar.Header, s source, want File) error {
	r, _, err := s.open()
	if err != nil {
		return err
	}
	defer r.Close()
	if err := tw.WriteHeader(h); err != nil {
		return err
	}
	sum := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tw, sum), io.LimitReader(r, want.Size)); err != nil {
		return err
	}
	if hex.EncodeToString(sum.Sum(nil)) != want.SHA256 {
		return fmt.Errorf("backup: %s changed while it was written", s.name)
	}
	return nil
}
