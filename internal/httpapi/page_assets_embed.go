//go:build !devfs

package httpapi

import (
	"embed"
	"io/fs"
)

// webassets is static/, copied into this package before the build
// (scripts/stage-webassets.sh). The directory is ignored by Git; without
// it the embed pattern matches nothing and the build fails.
//
//go:embed all:webassets
var webassets embed.FS

// StaticAssets indexes the embedded copy of static/.
func StaticAssets() (*Assets, error) {
	files, err := fs.Sub(webassets, "webassets")
	if err != nil {
		return nil, err
	}
	return NewAssets(files)
}
