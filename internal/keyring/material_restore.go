package keyring

import (
	"fmt"
	"path/filepath"
)

// MaterialLocation returns where the installation in dataDir keeps its
// keyring material and the material itself: the copy in go/ first, then
// the one in logs/.webssh-go/. Without any copy, material is nil and path
// is where LoadOrCreateMaterial would create it (logs/.webssh-go/ while
// legacyPresent). Two copies that differ are ErrMaterialConflict. It
// changes nothing.
func MaterialLocation(dataDir string, legacyPresent bool) (path string, material []byte, err error) {
	mp := pathsIn(dataDir)
	if err := mp.check(); err != nil {
		return "", nil, err
	}
	inGo, inState, err := mp.read()
	switch {
	case err != nil:
		return "", nil, err
	case inGo != nil:
		return mp.goFile, inGo, nil
	case inState != nil:
		return mp.stateFile, inState, nil
	case legacyPresent:
		return mp.stateFile, nil, nil
	}
	return mp.goFile, nil, nil
}

// InstallMaterial writes material to path, one of the two places
// MaterialLocation names, atomically: a temporary file in the same
// directory, fsynced, renamed over path, and the directory fsynced. A
// restore uses it to install the material of a restored archive.
func InstallMaterial(dataDir, path string, material []byte) error {
	if len(material) != MaterialSize {
		return fmt.Errorf("%w: %d bytes, want %d", ErrMaterialFile, len(material), MaterialSize)
	}
	mp := pathsIn(dataDir)
	var tmp string
	switch path {
	case mp.goFile:
		tmp = mp.goTmp
		if err := ensureDir(mp.goDir); err != nil {
			return err
		}
	case mp.stateFile:
		tmp = mp.stateTmp
		if err := ensureDir(filepath.Dir(mp.stateDir)); err != nil {
			return err
		}
		if err := ensureDir(mp.stateDir); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: %s is not a material location", ErrMaterialFile, path)
	}
	return installFile(tmp, path, material)
}

// ReadMaterialFile reads a material file written by InstallMaterial or a
// copy of one (mode 0600, the material size), without following a
// symlink. A missing file returns (nil, nil).
func ReadMaterialFile(path string) ([]byte, error) { return readMaterial(path) }
