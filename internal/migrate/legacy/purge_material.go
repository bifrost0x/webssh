package legacy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// moveMaterialAfterPurge moves the material into go/, removes the marker,
// moves the directories --replace set aside under logs/.webssh-go/ into
// go/ and removes logs/.webssh-go/ once it is empty (section 5.9, I-25).
func moveMaterialAfterPurge(ctx context.Context, l layout, secret string, db *store.DB, keyID string) error {
	if _, err := os.Lstat(l.stateDir); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	material, err := keyring.LoadOrCreateMaterial(l.dataDir, false)
	if err != nil {
		return err
	}
	ring, err := keyring.Open([]byte(secret), material)
	if err != nil {
		return err
	}
	err = keyring.MoveMaterialToGo(l.dataDir, ring, keyID, func() error {
		return db.Write(ctx, func(tx *store.Tx) error { return setMaterialInGo(ctx, tx) })
	})
	if err != nil {
		return err
	}
	if err := os.Remove(l.marker); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := syncDir(l.stateDir); err != nil {
		return err
	}
	if err := moveReplacedMaterial(l); err != nil {
		return err
	}
	entries, err := os.ReadDir(l.stateDir)
	if err != nil || len(entries) > 0 {
		return err
	}
	if err := os.Remove(l.stateDir); err != nil {
		return err
	}
	return syncDir(filepath.Dir(l.stateDir))
}

// moveReplacedMaterial moves each logs/.webssh-go/replaced-<UTC>/ into
// go/replaced-<UTC>/ beside the database it belongs to: every file is
// copied, read back and synced before the original is removed.
func moveReplacedMaterial(l layout) error {
	entries, err := os.ReadDir(l.stateDir)
	if err != nil {
		return err
	}
	for _, d := range entries {
		if !d.IsDir() || !strings.HasPrefix(d.Name(), replacedPrefx) {
			continue
		}
		src, dst := filepath.Join(l.stateDir, d.Name()), filepath.Join(l.goDir, d.Name())
		if err := ensurePrivateDir(dst); err != nil {
			return err
		}
		files, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, f := range files {
			if !f.Type().IsRegular() {
				return fmt.Errorf("%w: %s", ErrUnsafePath, filepath.Join(src, f.Name()))
			}
			if err := copyOnce(filepath.Join(src, f.Name()), filepath.Join(dst, f.Name())); err != nil {
				return err
			}
			if err := os.Remove(filepath.Join(src, f.Name())); err != nil {
				return err
			}
		}
		if err := errors.Join(syncDir(src), os.Remove(src), syncDir(l.stateDir)); err != nil {
			return err
		}
	}
	return nil
}

// copyOnce copies src to dst with copyVerified. A dst left by an
// interrupted move is kept when it holds the same bytes and copied again
// otherwise: src is removed only after a verified copy, so it is the
// authority while it exists.
func copyOnce(src, dst string) error {
	if _, err := os.Lstat(dst); err == nil {
		a, err1 := fileSHA256(src)
		b, err2 := fileSHA256(dst)
		if err := errors.Join(err1, err2); err != nil {
			return err
		}
		if a == b {
			return nil
		}
		if err := os.Remove(dst); err != nil {
			return err
		}
	}
	return copyVerified(src, dst)
}

// syncFile syncs an opened directory; Windows cannot sync a directory.
func syncFile(f *os.File) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	return f.Sync()
}
