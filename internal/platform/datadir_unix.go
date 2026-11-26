//go:build unix

package platform

import (
	"fmt"
	"os"
)

// restrictDir sets mode 0700. Changing the mode needs ownership, so a mount
// that belongs to another identity fails here, and the error carries the
// hint how to fix it.
func restrictDir(dir string) error {
	return os.Chmod(dir, 0o700) // #nosec G302 -- directories need the search bit; 0700 is owner-only
}

// ownershipHint names the numeric identity the process runs as. With
// --user 99:100 (Unraid) a fresh named volume is seeded from the image and
// belongs to 1000:1000, so the hint gives the exact chown to run.
func ownershipHint() string {
	id := RuntimeIdentity()
	return fmt.Sprintf("it must be owned and writable by the runtime user %s, for example: chown -R %s <host directory>", id, id)
}

// RuntimeIdentity returns the effective user and group ID as "uid:gid".
func RuntimeIdentity() string {
	return fmt.Sprintf("%d:%d", os.Geteuid(), os.Getegid())
}

// DescribeDataDir reports the mode of dir and the identity the process runs
// as, for the start-up log.
func DescribeDataDir(dir string) (string, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("mode=%04o runtime_user=%s", info.Mode().Perm(), RuntimeIdentity()), nil
}
