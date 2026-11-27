package backup

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// secretFileName is DATA_DIR/secret_key, the persisted SECRET_KEY.
const secretFileName = "secret_key"

// maxSecretFile bounds a secret file a rotation reads.
const maxSecretFile = 64 << 10

// errSecretFile reports a secret file that is not a plain, private file.
var errSecretFile = errors.New("backup: the secret file is not a regular file")

// checkSecret refuses a secret the entrypoint could not read back as the
// same value: empty, or with NUL, CR or LF.
func checkSecret(s []byte) error {
	if len(s) == 0 || len(s) > maxSecretFile || bytes.ContainsAny(s, "\x00\r\n") {
		return errors.New("backup: the new SECRET_KEY is invalid")
	}
	return nil
}

// readSecretFile reads a secret file written by installSecretFile,
// without following a symlink. A missing file is (nil, nil).
func readSecretFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("backup: %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s", errSecretFile, path)
	}
	f, err := os.Open(path) // #nosec G304 -- a fixed name below DATA_DIR
	if err != nil {
		return nil, fmt.Errorf("backup: %s: %w", path, err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxSecretFile+2))
	if err != nil {
		return nil, fmt.Errorf("backup: %s: %w", path, err)
	}
	secret := bytes.TrimSuffix(raw, []byte("\n"))
	if err := checkSecret(secret); err != nil {
		return nil, fmt.Errorf("%w: %s holds no valid secret", errSecretFile, path)
	}
	return secret, nil
}

// installSecretFile replaces path with secret and a line feed, mode 0600:
// written and fsynced under a temporary name in the same directory,
// renamed into place, the directory fsynced, then read back.
func installSecretFile(path string, secret []byte) error {
	dir := filepath.Dir(path)
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".tmp")
	if err := removeRegular(tmp); err != nil {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- a fixed name below DATA_DIR
	if err != nil {
		return fmt.Errorf("backup: create %s: %w", tmp, err)
	}
	_, werr := f.Write(append(bytes.Clone(secret), '\n'))
	if err := errors.Join(werr, f.Sync(), f.Close()); err != nil {
		return errors.Join(fmt.Errorf("backup: write %s: %w", tmp, err), removeRegular(tmp))
	}
	if err := os.Rename(tmp, path); err != nil {
		return errors.Join(fmt.Errorf("backup: install %s: %w", path, err), removeRegular(tmp))
	}
	if err := syncDir(dir); err != nil {
		return err
	}
	back, err := readSecretFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(back, secret) {
		return fmt.Errorf("%w: %s reads back differently", errSecretFile, path)
	}
	return nil
}

// removeRegular removes a regular file and fsyncs its directory; a
// missing file is not an error, anything else than a file is.
func removeRegular(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("backup: %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: %s", errSecretFile, path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("backup: remove %s: %w", path, err)
	}
	return syncDir(filepath.Dir(path))
}
