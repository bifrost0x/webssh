//go:build !devfs

package httpapi

import (
	"embed"
	"io/fs"
)

// webassets is static/, copied into this package before the build
// (scripts/stage-webassets.sh). Files starting with "." or "_" are left
// out, so editor and system files of a working copy are not shipped. The directory is ignored by Git; without
// it the embed pattern matches nothing and the build fails.
//
//go:embed webassets
var webassets embed.FS

// StaticAssets indexes the embedded copy of static/.
func StaticAssets() (*Assets, error) {
	files, err := fs.Sub(webassets, "webassets")
	if err != nil {
		return nil, err
	}
	return NewAssets(files)
}
