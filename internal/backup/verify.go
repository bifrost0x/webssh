package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// ErrInvalid reports an archive that fails verification.
var ErrInvalid = errors.New("backup: the archive does not verify")

// Probe opens one sealed record of a capability with ring and reports
// whether there was one (vault.ProbeSealed, totp.ProbeSealed).
type Probe func(ctx context.Context, tx *store.Tx, ring *keyring.Ring) (bool, error)

// Verified is the outcome of Verify.
type Verified struct {
	Manifest Manifest
	// SealedChecked is true when a probe found and opened a sealed
	// record; a database without sealed records has none to open.
	SealedChecked bool
}

// Verify reads an archive back: the manifest, the size and SHA-256 of
// every member, the integrity of the database, the key identifier of
// SECRET_KEY and the material, and one sealed record per probe until one
// is found. The database is checked on a temporary copy next to the
// archive, which is removed afterwards.
func Verify(ctx context.Context, path string, probes ...Probe) (Verified, error) {
	var v Verified
	f, err := os.Open(path) // #nosec G304 -- the archive Write created
	if err != nil {
		return v, fmt.Errorf("backup: open %s: %w", path, err)
	}
	defer f.Close()
	tmp, err := os.MkdirTemp(filepath.Dir(path), ".webssh-backup-verify-")
	if err != nil {
		return v, fmt.Errorf("backup: verify %s: %w", path, err)
	}
	defer os.RemoveAll(tmp)
	members, err := readMembers(tar.NewReader(f), &v.Manifest, filepath.Join(tmp, "webssh.db"))
	if err != nil {
		return v, err
	}
	ring, err := keyring.Open(members[SecretName], members[MaterialName])
	if err == nil {
		err = ring.Verify(v.Manifest.KeyID)
	}
	if err != nil {
		return v, fmt.Errorf("%w: SECRET_KEY and the material do not match the key id: %w", ErrInvalid, err)
	}
	v.SealedChecked, err = checkDatabase(ctx, filepath.Join(tmp, "webssh.db"), ring, probes)
	return v, err
}

// readMembers checks the manifest and every member. The database is
// written to dbCopy, the small members are returned.
func readMembers(tr *tar.Reader, m *Manifest, dbCopy string) (map[string][]byte, error) {
	h, err := tr.Next()
	if err != nil || h.Name != ManifestName || h.Size > maxManifest {
		return nil, fmt.Errorf("%w: the first member is not the manifest", ErrInvalid)
	}
	raw, err := io.ReadAll(io.LimitReader(tr, maxManifest))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if err := json.Unmarshal(raw, m); err != nil {
		return nil, fmt.Errorf("%w: manifest: %w", ErrInvalid, err)
	}
	if m.Format != FormatName || m.Version != FormatVersion || !m.IncludesSecretKey || m.KeyID == "" {
		return nil, fmt.Errorf("%w: unsupported manifest", ErrInvalid)
	}
	want := []string{DatabaseName, SecretName, MaterialName}
	small := map[string][]byte{}
	seen := 0
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
		}
		i := slices.IndexFunc(m.Files, func(f File) bool { return f.Name == h.Name })
		if i < 0 || seen >= len(want) || want[seen] != h.Name || h.Typeflag != tar.TypeReg || h.Size != m.Files[i].Size {
			return nil, fmt.Errorf("%w: unexpected member %q", ErrInvalid, h.Name)
		}
		seen++
		var dst io.Writer
		var buf bytes.Buffer
		var out *os.File
		if h.Name == DatabaseName {
			if out, err = os.OpenFile(dbCopy, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600); err != nil { // #nosec G304 -- a private temporary directory
				return nil, err
			}
			dst = out
		} else {
			if h.Size > keyring.MaterialSize*1024 {
				return nil, fmt.Errorf("%w: member %q is too large", ErrInvalid, h.Name)
			}
			dst = &buf
		}
		sum := sha256.New()
		_, err = io.Copy(io.MultiWriter(dst, sum), tr)
		if out != nil {
			err = errors.Join(err, out.Close())
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
		}
		if hex.EncodeToString(sum.Sum(nil)) != m.Files[i].SHA256 {
			return nil, fmt.Errorf("%w: %s does not match its hash", ErrInvalid, h.Name)
		}
		if out == nil {
			small[h.Name] = buf.Bytes()
		}
	}
	if seen != len(want) || len(m.Files) != len(want) {
		return nil, fmt.Errorf("%w: members are missing", ErrInvalid)
	}
	return small, nil
}

func checkDatabase(ctx context.Context, path string, ring *keyring.Ring, probes []Probe) (bool, error) {
	db, err := store.Open(ctx, path, store.Options{})
	if err != nil {
		return false, fmt.Errorf("%w: database: %w", ErrInvalid, err)
	}
	defer db.Close()
	if err := db.IntegrityCheck(ctx); err != nil {
		return false, fmt.Errorf("%w: database: %w", ErrInvalid, err)
	}
	checked := false
	err = db.Read(ctx, func(tx *store.Tx) error {
		for _, p := range probes {
			found, err := p(ctx, tx, ring)
			if err != nil {
				return err
			}
			if found {
				checked = true
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("%w: sealed record: %w", ErrInvalid, err)
	}
	return checked, nil
}

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

// syncDir makes the new archive's directory entry durable. Windows cannot
// sync a directory.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir) // #nosec G304 -- the backup target
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}
