package files

import (
	"context"
	"io"
	"io/fs"
	"time"
)

// Backend is one open file source: an SFTP subsystem on an SSH
// connection or an SMB share. Paths are canonical (Clean or CleanTarget)
// and relative to the source root, which is "/" of the SFTP server or the
// SMB share. Every method honours the deadline and the cancellation of
// ctx. Failures are *fault.Error values with the file codes of the
// catalog (fault.FileNotFound, fault.FileConflict, fault.OutcomeUnknown,
// …); a backend never puts remote-supplied text or paths into a message.
//
// A Backend is safe for concurrent use. After Close every method fails
// with fault.SourceUnavailable.
type Backend interface {
	// Capabilities reports what the source supports. It does not change
	// while the source is open.
	Capabilities() Capabilities

	// Home returns the start directory: the login directory of the SFTP
	// user, "/" for SMB.
	Home(ctx context.Context) (string, error)

	// OpenListing starts reading the directory at path. Entries come in
	// server order without "." and ".."; the caller pages through them
	// and closes the listing. The listing holds server resources until
	// Close.
	OpenListing(ctx context.Context, path string) (Listing, error)

	// Stat describes path. With follow false a symbolic link (an SMB
	// reparse point) is described itself; with follow true its target,
	// which SMB refuses with fault.SMBReparsePointRejected.
	Stat(ctx context.Context, path string, follow bool) (Entry, error)

	// Open reads the regular file at path from r.Offset. A directory or a
	// link fails with fault.UnsupportedOperation.
	Open(ctx context.Context, path string, r Range) (Reader, error)

	// Write stores the bytes of src at path as one replacement: readers see
	// the old or the new content, never a part (WriteOptions).
	Write(ctx context.Context, path string, src io.Reader, o WriteOptions) (WriteResult, error)

	// Mkdir creates one directory; the parent must exist.
	Mkdir(ctx context.Context, path string) error

	// Rename moves from to to. It never replaces: an existing to fails
	// with fault.FileConflict. A lost reply after the request was sent
	// fails with fault.OutcomeUnknown.
	Rename(ctx context.Context, from, to string) error

	// Remove deletes a file, a link or an empty directory; with recursive
	// it deletes a tree within b, without following links. A partly
	// deleted tree is not restored.
	Remove(ctx context.Context, path string, recursive bool, b Budget) error

	// Walk visits path and every entry below it, parents before children,
	// without following links, within b. fn returning an error stops the
	// walk with that error.
	Walk(ctx context.Context, path string, b Budget, fn func(Entry) error) error

	// Chmod sets the permission bits of path without following a link.
	// Without CapChmod it fails with fault.UnsupportedOperation; when the
	// mode read back differs it fails with fault.ModeMismatch.
	Chmod(ctx context.Context, path string, perm fs.FileMode) error

	// Close ends the source and every listing and reader on it.
	Close() error
}

// Listing is an open directory read.
type Listing interface {
	// Next returns up to max entries and whether more may follow.
	Next(ctx context.Context, max int) (entries []Entry, more bool, err error)
	Close() error
}

// Reader is an open file. Entry describes the file when it was opened.
type Reader interface {
	io.ReadCloser
	Entry() Entry
}

// AccessProber is implemented by backends that can tell, before a
// mutation, whether the account may list, create and delete in a
// directory (SMB, inspect_directory_access).
type AccessProber interface {
	Access(ctx context.Context, path string) (Access, error)
}

// Access values of the source descriptor.
const (
	AccessGranted = "granted"
	AccessDenied  = "denied"
	AccessUnknown = "unknown"
)

// Access is the result of an AccessProber.
type Access struct {
	List, CreateFile, CreateDirectory, DeleteChildren string
}

// Entry describes one file system object.
type Entry struct {
	Name string // last path element, as the server returned it
	Path string // canonical path below the source root
	Size int64
	// Mode is the POSIX st_mode with type bits as the page shows it; SMB
	// synthesises it (directory 0o040111, file 0o100444 or 0o100666).
	Mode      uint32
	IsDir     bool
	IsSymlink bool // a symbolic link, or an SMB reparse point
	ModTime   time.Time
	Owner     *Owner // nil when the server does not say
}

// Owner holds the numeric owner of an SFTP object. Names are never shown.
type Owner struct {
	UID, GID uint32
}

// Range selects a part of a file. Length below zero reads to the end.
type Range struct {
	Offset, Length int64
}

// Strategy is how Write replaces an existing file.
type Strategy string

const (
	// StrategyAtomic writes a temporary file beside the target and renames
	// it over the target in one step (SFTP posix-rename, SMB handle
	// rename). A source that cannot fails with
	// fault.AtomicReplaceUnavailable (transfers) or
	// fault.SMBRecoverableReplaceNeed (editor on SMB).
	StrategyAtomic Strategy = "atomic"
	// StrategyRecoverableSwap moves the target to a backup, installs the
	// new file and deletes the backup (SMB editor, after the user
	// confirmed it). Its failures are fault.SMBRecoverableReplaceFail and
	// fault.SMBRecoveryRequired with the recovery files in the details.
	StrategyRecoverableSwap Strategy = "recoverable_swap"
)

// WriteOptions control Write.
type WriteOptions struct {
	// Exclusive fails with fault.FileConflict when path exists (new files,
	// uploads with conflict policy "error").
	Exclusive bool
	// ExpectedRevision, when set, requires an existing file whose
	// Revision equals it; otherwise Write fails with fault.EditConflict.
	ExpectedRevision string
	Strategy         Strategy // StrategyAtomic when empty
	// FollowSymlink writes the target of a link at path and keeps the
	// link (editor on SFTP). Without it a link at path is refused.
	FollowSymlink bool
	// Size is the declared length of src, or -1. Fewer or more bytes fail
	// with fault.SourceChanged and leave the target unchanged.
	Size int64
	// MaxBytes bounds src (0: no bound beyond Size); more fails with
	// fault.LimitExceeded.
	MaxBytes int64
}

// WriteResult is the outcome of a Write that installed the new content.
type WriteResult struct {
	Revision string // Revision of the bytes written
	Size     int64
	// Warning is set when the content is installed but a leftover remains
	// (WarningRecoveryBackupRetained); RecoveryLeaves names its files.
	Warning        string
	RecoveryLeaves []string
}

// WarningRecoveryBackupRetained is the warning of a recoverable swap whose
// backup could not be deleted (Python spelling).
const WarningRecoveryBackupRetained = "SMB_RECOVERY_BACKUP_RETAINED"

// Budget bounds a tree operation. Zero fields take the defaults.
type Budget struct {
	MaxMembers int   // entries visited (DefaultMaxMembers)
	MaxDepth   int   // directory levels below the start (DefaultMaxDepth)
	MaxBytes   int64 // sum of file sizes, 0 for no bound
}

// Defaults of a Budget, as in the Python release (MAX_TRANSFER_MEMBERS and
// the depth of the recursive delete and copy).
const (
	DefaultMaxMembers = 10000
	DefaultMaxDepth   = 50
)

// WithDefaults returns b with zero fields set to the defaults.
func (b Budget) WithDefaults() Budget {
	if b.MaxMembers <= 0 {
		b.MaxMembers = DefaultMaxMembers
	}
	if b.MaxDepth <= 0 {
		b.MaxDepth = DefaultMaxDepth
	}
	return b
}
