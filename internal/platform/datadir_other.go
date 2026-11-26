//go:build !unix

package platform

import (
	"errors"
	"fmt"
	"os"
)

// errNoOwnerOnlyAccess is returned until owner-only access is implemented
// for the platform. Starting with a data directory that others may read
// would expose the database and keys, so preparation fails instead.
var errNoOwnerOnlyAccess = fmt.Errorf("owner-only access is not implemented on this platform: %w", errors.ErrUnsupported)

func restrictDir(string) error { return errNoOwnerOnlyAccess }

func ownershipHint() string { return "" }

// RuntimeIdentity is empty where processes have no numeric identity.
func RuntimeIdentity() string { return "" }

// DescribeDataDir reports the mode bits of dir.
func DescribeDataDir(dir string) (string, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("mode=%04o", info.Mode().Perm()), nil
}
