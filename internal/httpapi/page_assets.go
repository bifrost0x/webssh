package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"slices"
	"strings"
)

// Assets indexes the application's static files: the files of static/,
// embedded at build time or, with the devfs build tag, read from the
// source tree. Every file has a content version, the first 16 hex digits
// of its SHA-256, the same value Python appends as ?v= so that cached
// URLs stay valid across the switch.
type Assets struct {
	files        fs.FS
	versions     map[string]string
	translations []string
}

// errNoAssets reports an asset tree without files, usually a build that
// skipped staging static/.
var errNoAssets = errors.New("static assets are missing; stage static/ into internal/httpapi/webassets before building")

// NewAssets indexes every regular file of files. Paths use forward
// slashes and are relative to the root of files.
func NewAssets(files fs.FS) (*Assets, error) {
	a := &Assets{files: files, versions: map[string]string{}}
	err := fs.WalkDir(files, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		version, err := contentVersion(files, name)
		if err != nil {
			return err
		}
		a.versions[name] = version
		if dir, file := path.Split(name); dir == "js/i18n/" && strings.HasSuffix(file, ".js") {
			a.translations = append(a.translations, strings.TrimSuffix(file, ".js"))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("index static assets: %w", err)
	}
	if len(a.versions) == 0 {
		return nil, errNoAssets
	}
	slices.Sort(a.translations)
	return a, nil
}

func contentVersion(files fs.FS, name string) (string, error) {
	f, err := files.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("read %s: %w", name, err)
	}
	return hex.EncodeToString(h.Sum(nil))[:16], nil
}

// Version returns the content version of a file.
func (a *Assets) Version(name string) (string, bool) {
	v, ok := a.versions[name]
	return v, ok
}

// Translations lists the languages with a file in js/i18n/, sorted.
func (a *Assets) Translations() []string {
	return slices.Clone(a.translations)
}

// FS returns the indexed files for the static file handler.
func (a *Assets) FS() fs.FS {
	return a.files
}
