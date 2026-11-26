package keyring

import (
	"bytes"
	"errors"
	"path/filepath"
)

// MoveMaterialToState moves the material of r from go/ to logs/.webssh-go/
// while legacy data exists. This happens when the material reached go/
// beside legacy data, for example by copying a data directory by hand or
// by restoring a Python backup onto a new installation: in go/ it would be
// part of every Python export, next to SECRET_KEY, and make the sealed
// secrets in that export readable (migration specification, section 2.2).
//
// The order is the one of MoveMaterialToGo in reverse (I-25): write and
// fsync logs/.webssh-go/.keyring-material.tmp, read it back, rename it to
// logs/.webssh-go/keyring-material and fsync the directory, and only then
// remove go/keyring-material and fsync go/. At every moment one complete
// copy exists; two identical copies after a crash are resolved by calling
// it again, two differing ones are ErrMaterialConflict (state S9).
//
// storedKeyID is the key identifier of the Go database, checked first; ""
// means no Go database exists. It reports whether a copy in go/ was
// removed. The caller holds the Go lock.
func MoveMaterialToState(dataDir string, r *Ring, storedKeyID string) (bool, error) {
	if storedKeyID != "" {
		if err := r.Verify(storedKeyID); err != nil {
			return false, err
		}
	}
	mp := pathsIn(dataDir)
	if err := mp.check(); err != nil {
		return false, err
	}
	inGo, inState, err := mp.read()
	if err != nil || inGo == nil {
		return false, err
	}
	if !bytes.Equal(inGo, r.material[:]) {
		return false, ErrKeyMismatch
	}
	if inState == nil {
		if err := errors.Join(ensureDir(filepath.Dir(mp.stateDir)), ensureDir(mp.stateDir)); err != nil {
			return false, err
		}
		if err := installFile(mp.stateTmp, mp.stateFile, inGo); err != nil {
			return false, err
		}
	}
	return true, removeFile(mp.goFile)
}
