package legacy

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
	"time"
)

// openNonblock makes opening a FIFO return at once instead of waiting
// for a writer.
const openNonblock = syscall.O_NONBLOCK

// syncDir fsyncs a directory so that a created, renamed or removed entry
// survives a crash.
func syncDir(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- a Go-owned directory below DATA_DIR
	if err != nil {
		return fmt.Errorf("legacy: sync %s: %w", dir, err)
	}
	serr := d.Sync()
	cerr := d.Close()
	if err := errors.Join(serr, cerr); err != nil {
		return fmt.Errorf("legacy: sync %s: %w", dir, err)
	}
	return nil
}

// How long acquireLock waits for a held lock, and how often it asks.
const (
	lockWait = time.Second
	lockPoll = 20 * time.Millisecond
)

// goLock is an exclusive flock on the Go lock file. The kernel releases it
// when the process ends, however it ends.
type goLock struct{ f *os.File }

func acquireLock(path string) (*goLock, error) { return openLock(path, os.O_CREATE) }

// acquireExistingLock takes the lock only where the lock file exists and
// returns nil without creating it otherwise: a dry run writes nothing to
// DATA_DIR, and every Go process that uses the directory creates the file
// before it holds the lock.
func acquireExistingLock(path string) (*goLock, error) {
	l, err := openLock(path, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return l, err
}

func openLock(path string, create int) (*goLock, error) {
	f, err := os.OpenFile(path, os.O_RDWR|create|syscall.O_NOFOLLOW, 0o600) // #nosec G304 -- the Go-owned lock file
	if err != nil {
		return nil, fmt.Errorf("legacy: open lock file: %w", err)
	}
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		return nil, errors.Join(fmt.Errorf("%w: %s", ErrUnsafePath, path), f.Close())
	}
	// A lock released a moment ago can still be held by a child process
	// between fork and exec, which shares the descriptor; a short retry
	// covers that window.
	deadline := time.Now().Add(lockWait)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) // #nosec G115 -- a file descriptor fits into int
		switch {
		case err == nil:
			return &goLock{f: f}, nil
		case errors.Is(err, syscall.EWOULDBLOCK) && time.Now().Before(deadline):
			time.Sleep(lockPoll)
		case errors.Is(err, syscall.EWOULDBLOCK):
			return nil, errors.Join(ErrLocked, f.Close())
		default:
			return nil, errors.Join(fmt.Errorf("legacy: lock %s: %w", path, err), f.Close())
		}
	}
}

// release releases the lock; a nil lock (acquireExistingLock without a
// lock file) has nothing to release.
func (l *goLock) release() error {
	if l == nil {
		return nil
	}
	return l.f.Close()
}

// probeSQLiteLock reports whether another process holds any SQLite lock on
// the database file at path: a pending, reserved or shared lock, which
// Python holds in the middle of a transaction. It asks with F_GETLK on a
// read-only descriptor, which changes nothing. The caller must not have
// the database open itself: closing this descriptor would drop POSIX locks
// the process holds on the same file.
func probeSQLiteLock(path string) (bool, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- DATA_DIR/app.db
	if err != nil {
		return false, fmt.Errorf("legacy: open app.db for the lock probe: %w", err)
	}
	defer f.Close()
	// SQLite's lock bytes (os_unix.c): PENDING_BYTE at 1 GiB, then the
	// reserved byte and 510 shared bytes.
	const pendingByte, lockBytes = 0x40000000, 512
	lk := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: 0, Start: pendingByte, Len: lockBytes}
	if err := syscall.FcntlFlock(f.Fd(), syscall.F_GETLK, &lk); err != nil {
		return false, fmt.Errorf("legacy: probe the lock of app.db: %w", err)
	}
	return lk.Type != syscall.F_UNLCK, nil
}

// probeFlock reports whether another process holds the flock of the
// Python backup operation lock (app/backup_coordination.py). A missing
// file is not held. It never creates the file.
func probeFlock(path string) (bool, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- BACKUP_TEMP_DIR/instance-*/operation.lock
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("legacy: open %s: %w", path, err)
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		return false, fmt.Errorf("%w: %s", ErrUnsafePath, path)
	}
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) // #nosec G115 -- a file descriptor fits into int
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("legacy: probe %s: %w", path, err)
	}
	return false, syscall.Flock(int(f.Fd()), syscall.LOCK_UN) // #nosec G115 -- a file descriptor fits into int
}

// freeBytes returns the space available to this process on the file
// system of dir.
func freeBytes(dir string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, fmt.Errorf("legacy: free space of %s: %w", dir, err)
	}
	return st.Bavail * uint64(st.Bsize), nil // #nosec G115 -- the block size is positive
}

// fileIdentity returns the inode of a file for the digest's fast path.
func fileIdentity(info os.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}
