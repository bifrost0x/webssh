//go:build devfs

package httpapi

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

// StaticAssets reads static/ from the source tree, so that edits to
// scripts and styles show without a rebuild. Development only: the path
// comes from the location of this source file and does not exist in a
// release build.
func StaticAssets() (*Assets, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return nil, errors.New("devfs: cannot locate the source tree")
	}
	if !filepath.IsAbs(file) {
		return nil, errors.New("devfs: source path is not absolute; build without -trimpath")
	}
	// os.Root keeps every open, symlinks included, inside static/.
	root, err := os.OpenRoot(filepath.Join(filepath.Dir(file), "..", "..", "static"))
	if err != nil {
		return nil, err
	}
	return NewAssets(root.FS())
}
