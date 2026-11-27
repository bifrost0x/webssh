package keyring

import (
	"fmt"
	"os"
)

// syncDir fsyncs a directory so that a created, renamed or removed entry
// survives a crash.
func syncDir(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- a directory below the configured DATA_DIR
	if err != nil {
		return fmt.Errorf("keyring: sync %s: %w", dir, err)
	}
	serr := d.Sync()
	cerr := d.Close()
	if serr != nil {
		return fmt.Errorf("keyring: sync %s: %w", dir, serr)
	}
	if cerr != nil {
		return fmt.Errorf("keyring: sync %s: %w", dir, cerr)
	}
	return nil
}
