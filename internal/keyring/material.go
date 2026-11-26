package keyring

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
)

// Layout of the keyring material below DATA_DIR (migration specification,
// sections 2 and 2.2). The material lives under logs/.webssh-go/ while
// legacy data exists, because Python 3.3.x never exports logs/, and in go/
// otherwise. The Go directory and database names are shared with the
// migration and the composition root.
const (
	goDirName      = "go"
	databaseName   = "webssh.db"
	logsDirName    = "logs"
	stateDirName   = ".webssh-go"
	materialName   = "keyring-material"
	materialTmp    = ".keyring-material.tmp"
	materialHelpGo = "go/" + materialName
	materialHelpLg = "logs/" + stateDirName + "/" + materialName
)

// Errors of the material files. Both are state S9: Go stops and changes
// nothing.
var (
	// ErrMaterialMissing reports a Go database without keyring material.
	// Go never creates new material while a Go database exists.
	ErrMaterialMissing = errors.New("keyring: the keyring material is missing (" + materialHelpGo + " and " +
		materialHelpLg + "), but a Go database exists; sealed SSH keys, saved passwords and second factors " +
		"cannot be read without it. Restore the file from a volume backup; while the legacy data exists, " +
		"`webssh migrate --replace` migrates again from it; after `webssh legacy purge`, restore the Go " +
		"backup the purge wrote, which contains the material")
	// ErrMaterialConflict reports two copies of the material that differ.
	ErrMaterialConflict = errors.New("keyring: " + materialHelpGo + " and " + materialHelpLg +
		" differ; keep the copy that belongs to the Go database and move the other one away")
)

type materialPaths struct {
	goDir, stateDir, goFile, goTmp, stateFile, stateTmp string
}

func pathsIn(dataDir string) materialPaths {
	goDir := filepath.Join(dataDir, goDirName)
	stateDir := filepath.Join(dataDir, logsDirName, stateDirName)
	return materialPaths{
		goDir:     goDir,
		stateDir:  stateDir,
		goFile:    filepath.Join(goDir, materialName),
		goTmp:     filepath.Join(goDir, materialTmp),
		stateFile: filepath.Join(stateDir, materialName),
		stateTmp:  filepath.Join(stateDir, materialTmp),
	}
}

// check fails when the Go directory or the state directory is not a plain
// directory.
func (mp materialPaths) check() error {
	for _, dir := range []string{mp.goDir, filepath.Dir(mp.stateDir), mp.stateDir} {
		if err := checkDir(dir); err != nil {
			return err
		}
	}
	return nil
}

// databaseExists reports whether a Go database, or a side file of one,
// is in the Go directory. Staging databases and replaced databases do not
// count (migration spec, 5.2 step 7 and 5.4).
func (mp materialPaths) databaseExists() (bool, error) {
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		ok, err := exists(filepath.Join(mp.goDir, databaseName+suffix))
		if ok || err != nil {
			return ok, err
		}
	}
	return false, nil
}

// LoadOrCreateMaterial returns the keyring material of the installation in
// dataDir. It looks in go/ first, then in logs/.webssh-go/. Two copies
// that differ are ErrMaterialConflict. The only change it makes to
// existing files is removing a leftover temporary copy (section 5.9), which
// is never the only copy: it removes no material, so that a stop in state
// S9 changes nothing. Of two identical copies, the one under logs/ is
// removed by MoveMaterialToGo once the ring is verified.
//
// Without any copy it creates 32 random bytes, under logs/.webssh-go/ when
// legacyPresent and in go/ otherwise, written completely and fsynced
// before it returns, but only when no Go database exists; otherwise it
// returns ErrMaterialMissing. The caller holds the Go lock and checks the
// result against the database with Ring.Verify.
func LoadOrCreateMaterial(dataDir string, legacyPresent bool) ([]byte, error) {
	mp := pathsIn(dataDir)
	if err := mp.check(); err != nil {
		return nil, err
	}
	if err := errors.Join(removeFile(mp.goTmp), removeFile(mp.stateTmp)); err != nil {
		return nil, err
	}
	inGo, inState, err := mp.read()
	if err != nil {
		return nil, err
	}
	switch {
	case inGo != nil:
		return inGo, nil
	case inState != nil:
		return inState, nil
	}
	dbExists, err := mp.databaseExists()
	if err != nil {
		return nil, err
	}
	if dbExists {
		return nil, ErrMaterialMissing
	}
	return mp.create(dataDir, legacyPresent)
}

// read returns both copies; two that differ are ErrMaterialConflict.
func (mp materialPaths) read() (inGo, inState []byte, err error) {
	if inGo, err = readMaterial(mp.goFile); err != nil {
		return nil, nil, err
	}
	if inState, err = readMaterial(mp.stateFile); err != nil {
		return nil, nil, err
	}
	if inGo != nil && inState != nil && !bytes.Equal(inGo, inState) {
		return nil, nil, ErrMaterialConflict
	}
	return inGo, inState, nil
}

func (mp materialPaths) create(dataDir string, legacyPresent bool) ([]byte, error) {
	if err := checkDir(dataDir); err != nil {
		return nil, err
	}
	material := make([]byte, MaterialSize)
	if _, err := rand.Read(material); err != nil {
		return nil, fmt.Errorf("keyring: random material: %w", err)
	}
	if legacyPresent {
		if err := errors.Join(ensureDir(filepath.Dir(mp.stateDir)), ensureDir(mp.stateDir)); err != nil {
			return nil, err
		}
		return material, installFile(mp.stateTmp, mp.stateFile, material)
	}
	if err := ensureDir(mp.goDir); err != nil {
		return nil, err
	}
	return material, installFile(mp.goTmp, mp.goFile, material)
}

// MoveMaterialToGo moves the material of r from logs/.webssh-go/ to go/
// after `webssh legacy purge` (migration specification, section 5.9, I-25):
// it writes and fsyncs go/.keyring-material.tmp, checks that it reads back
// as r's material, renames it to go/keyring-material and fsyncs go/, calls
// record to note "material in go/" in the database, and only then removes
// the copy under logs/. At every moment one verified copy exists.
//
// It first checks r against storedKeyID, the key identifier in the
// database. It is idempotent: a move interrupted at any step is completed
// by calling it again, so record must be idempotent too. Removing the marker and the
// state directory is left to the caller, which owns the marker.
func MoveMaterialToGo(dataDir string, r *Ring, storedKeyID string, record func() error) error {
	if err := r.Verify(storedKeyID); err != nil {
		return err
	}
	mp := pathsIn(dataDir)
	if err := mp.check(); err != nil {
		return err
	}
	inGo, inState, err := mp.read()
	if err != nil {
		return err
	}
	want := r.material[:]
	switch {
	case inGo == nil && inState == nil:
		return ErrMaterialMissing
	case !bytes.Equal(firstOf(inGo, inState), want):
		return ErrKeyMismatch
	case inGo == nil:
		if err := ensureDir(mp.goDir); err != nil {
			return err
		}
		if err := installFile(mp.goTmp, mp.goFile, want); err != nil {
			return err
		}
	}
	if err := record(); err != nil {
		return fmt.Errorf("keyring: record the material in go/: %w", err)
	}
	return removeFile(mp.stateFile)
}

func firstOf(a, b []byte) []byte {
	if a != nil {
		return a
	}
	return b
}
