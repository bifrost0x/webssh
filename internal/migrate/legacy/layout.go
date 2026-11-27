package legacy

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bifrost0x/webssh/internal/keyring"
)

// Names of the Go-owned paths the migration manages (migration
// specification, section 2). The Go directory, the database, the state
// directory and the material come from internal/keyring, the one source
// of those names.
const (
	lockName      = "webssh.lock"
	stagingPrefix = ".migration-"
	reportPrefix  = "migration-report-"
	replacedPrefx = "replaced-"
	markerName    = "migrated"
	markerTmpName = ".migrated.tmp"
	stagedDBName  = keyring.DatabaseName
	utcStamp      = "20060102T150405.000000000Z"
)

// layout holds the absolute paths of one DATA_DIR.
type layout struct {
	dataDir, goDir, database, lock, stateDir, marker string
}

func layoutOf(dataDir string) (layout, error) {
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		return layout{}, fmt.Errorf("legacy: resolve data directory: %w", err)
	}
	goDir := filepath.Join(abs, keyring.GoDirName)
	stateDir := filepath.Join(abs, keyring.LogsDirName, keyring.StateDirName)
	return layout{
		dataDir:  abs,
		goDir:    goDir,
		database: filepath.Join(goDir, keyring.DatabaseName),
		lock:     filepath.Join(goDir, lockName),
		stateDir: stateDir,
		marker:   filepath.Join(stateDir, markerName),
	}, nil
}

// sideFiles are the SQLite files that may belong to a database.
var sideFiles = []string{"-wal", "-shm", "-journal"}

// databasePresent reports whether the Go database exists. Side files
// without a database are stale; activation moves them aside. Anything but
// a regular file at either name is ErrUnsafePath: the Go directory holds
// only regular files and directories (section 2.1).
func (l layout) databasePresent() (bool, error) {
	found := false
	for _, suffix := range append([]string{""}, sideFiles...) {
		info, err := os.Lstat(l.database + suffix)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, fmt.Errorf("legacy: inspect %s: %w", l.database+suffix, err)
		}
		if !info.Mode().IsRegular() {
			return false, fmt.Errorf("%w: %s", ErrUnsafePath, l.database+suffix)
		}
		found = found || suffix == ""
	}
	return found, nil
}

// ensureGoDir creates the Go directory, checks that it is a plain
// directory and restricts it to mode 0700, also when a Python restore or
// an operator created it with other modes (section 2).
func (l layout) ensureGoDir() error { return ensurePrivateDir(l.goDir) }

// ensureStateDir creates logs/ and logs/.webssh-go/ with mode 0700 and
// restricts the state directory to 0700.
func (l layout) ensureStateDir() error {
	if err := ensurePlainDir(filepath.Dir(l.stateDir)); err != nil {
		return err
	}
	return ensurePrivateDir(l.stateDir)
}

func ensurePrivateDir(dir string) error {
	if err := ensurePlainDir(dir); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("legacy: inspect %s: %w", dir, err)
	}
	if info.Mode().Perm() == 0o700 {
		return nil
	}
	if err := os.Chmod(dir, 0o700); err != nil { // #nosec G302 -- a directory needs the search bit; 0700 is owner-only
		return fmt.Errorf("legacy: restrict %s to its owner: %w", dir, err)
	}
	return nil
}

func ensurePlainDir(dir string) error {
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("legacy: create %s: %w", dir, err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("legacy: inspect %s: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrUnsafePath, dir)
	}
	return nil
}

// stagingDirs lists the staging directories left in the Go directory
// (state S6).
func (l layout) stagingDirs() ([]string, error) {
	entries, err := os.ReadDir(l.goDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("legacy: list %s: %w", l.goDir, err)
	}
	var dirs []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), stagingPrefix) {
			dirs = append(dirs, filepath.Join(l.goDir, e.Name()))
		}
	}
	return dirs, nil
}

// newStaging creates <Go directory>/.migration-<random>/ with mode 0700.
func (l layout) newStaging() (string, error) {
	if err := l.ensureGoDir(); err != nil {
		return "", err
	}
	var b [8]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails
	dir := filepath.Join(l.goDir, stagingPrefix+hex.EncodeToString(b[:]))
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", fmt.Errorf("legacy: create staging directory: %w", err)
	}
	return dir, nil
}

// removeStaging removes a staging directory. It refuses any path that is
// not a staging directory directly below the Go directory, so that a
// mistake can never remove other data.
func (l layout) removeStaging(dir string) error {
	if filepath.Dir(dir) != l.goDir || !strings.HasPrefix(filepath.Base(dir), stagingPrefix) {
		return fmt.Errorf("legacy: refusing to remove %s: not a staging directory", dir)
	}
	info, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("legacy: inspect %s: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: %s", ErrUnsafePath, dir)
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("legacy: remove staging directory: %w", err)
	}
	return syncDir(l.goDir)
}

// replacedDir creates <Go directory>/replaced-<UTC>/ for files moved out of
// the way (sections 5.2 step 10.4 and 5.4).
func (l layout) replacedDir(now time.Time) (string, error) {
	dir := filepath.Join(l.goDir, replacedPrefx+now.UTC().Format(utcStamp))
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", fmt.Errorf("legacy: create %s: %w", dir, err)
	}
	return dir, nil
}

// stateReplacedDir creates logs/.webssh-go/replaced-<UTC>/ for keyring
// material --replace sets aside: like the material itself it must stay out
// of go/, which Python exports.
func (l layout) stateReplacedDir(now time.Time) (string, error) {
	if err := l.ensureStateDir(); err != nil {
		return "", err
	}
	dir := filepath.Join(l.stateDir, replacedPrefx+now.UTC().Format(utcStamp))
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", fmt.Errorf("legacy: create %s: %w", dir, err)
	}
	return dir, nil
}

// replacedDatabases lists the databases --replace kept in go/replaced-*/:
// Go backups, and the byte copies of earlier releases and of S9.
func (l layout) replacedDatabases() []string {
	found, _ := filepath.Glob(filepath.Join(l.goDir, replacedPrefx+"*", keyring.DatabaseName))
	archives, _ := filepath.Glob(filepath.Join(l.goDir, replacedPrefx+"*", "webssh-backup-*.tar"))
	return append(found, archives...)
}
