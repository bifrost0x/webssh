//go:build windows

package legacy

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// syncDir is a no-op on Windows: directories cannot be opened for fsync
// there, and NTFS journals renames and deletions itself.
func syncDir(string) error { return nil }

// goLock is the Go lock file opened without sharing: a second open fails
// until the handle is closed, which Windows does when the process ends.
type goLock struct{ h syscall.Handle }

func acquireLock(path string) (*goLock, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("legacy: lock file name: %w", err)
	}
	h, err := syscall.CreateFile(name, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil,
		syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if errors.Is(err, errSharingViolation) {
		return nil, ErrLocked
	}
	if err != nil {
		return nil, fmt.Errorf("legacy: lock %s: %w", path, err)
	}
	return &goLock{h: h}, nil
}

// errSharingViolation is ERROR_SHARING_VIOLATION, which syscall does not
// name.
const errSharingViolation = syscall.Errno(32)

func (l *goLock) release() error { return syscall.CloseHandle(l.h) }

// errProbeUnsupported reports a probe this platform does not have; the
// second digest comparison still guards the migration.
var errProbeUnsupported = errors.New("legacy: this check is not available on Windows")

func probeSQLiteLock(string) (bool, error) { return false, errProbeUnsupported }

func probeFlock(string) (bool, error) { return false, errProbeUnsupported }

// freeBytes is not available on Windows without unsafe or
// golang.org/x/sys/windows; the migration then reports that the space was
// not checked, and a full disk during the staging writes still stops the
// migration and removes the staging directory.
func freeBytes(string) (uint64, error) { return 0, errProbeUnsupported }

// fileIdentity has no inode on Windows; the fast path relies on size and
// modification time there.
func fileIdentity(os.FileInfo) uint64 { return 0 }
