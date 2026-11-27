package backup

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Operation kinds (backup_operations.py).
const (
	KindCreated  = "created_backup"
	KindUploaded = "uploaded_backup"
)

// errNoOperation answers every lookup that fails: unknown, expired, owned
// by another account or session, or in the wrong state.
var errNoOperation = errors.New("backup: operation not found")

// errBusy reports that another backup or restore operation is active.
var errBusy = errors.New("backup: another backup or restore operation is active")

// Operation is one online backup or upload (an in-memory record, as in
// the Python release; its files live in a private directory below the
// Go namespace of BACKUP_TEMP_DIR and are removed with it).
type Operation struct {
	ID      string
	Kind    string
	Status  OperationStatus
	Size    int64
	Summary *Summary
	Error   string

	owner   int64
	session string
	dir     string
	expires time.Time
	confirm string
	confirmExpires time.Time
}

// Archive is the operation's archive file.
func (o Operation) Archive() string { return filepath.Join(o.dir, "archive") }

// Dir is the operation's private directory.
func (o Operation) Dir() string { return o.dir }

// Operations is the registry of online backup operations: at most one is
// active at a time, each belongs to the administrator and browser session
// that started it, and finished ones expire after BACKUP_DOWNLOAD_TTL.
type Operations struct {
	mu      sync.Mutex
	root    string
	records map[string]*Operation
	timeout time.Duration // BACKUP_OPERATION_TIMEOUT
	ttl     time.Duration // BACKUP_DOWNLOAD_TTL
	now     func() time.Time
}

// NewOperations opens the registry on root, a private directory (0700)
// it creates if needed. Operation directories left by an earlier process
// are removed: the records of a process do not survive it.
func NewOperations(root string, timeout, ttl time.Duration) (*Operations, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("backup: create %s: %w", root, err)
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() {
		return nil, errors.Join(fmt.Errorf("backup: %s is not a directory", root), err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "operation-") {
			if err := os.RemoveAll(filepath.Join(root, e.Name())); err != nil {
				return nil, err
			}
		}
	}
	return &Operations{root: root, records: map[string]*Operation{}, timeout: timeout, ttl: ttl, now: time.Now}, nil
}

// Root is the directory below which the operations live.
func (o *Operations) Root() string { return o.root }

func newToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// Create starts an operation for the administrator and session; it fails
// with errBusy while another operation is active.
func (o *Operations) Create(kind string, owner int64, session string, status OperationStatus) (Operation, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.sweepLocked()
	for _, r := range o.records {
		if r.Status.Active() {
			return Operation{}, errBusy
		}
	}
	id := newToken()[:43]
	dir := filepath.Join(o.root, "operation-"+id)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return Operation{}, fmt.Errorf("backup: allocate the operation: %w", err)
	}
	r := &Operation{ID: id, Kind: kind, Status: status, owner: owner, session: session, dir: dir,
		expires: o.now().Add(o.timeout)}
	o.records[id] = r
	return *r, nil
}

// Get returns the operation if it belongs to owner and session.
func (o *Operations) Get(id string, owner int64, session string) (Operation, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	r, err := o.getLocked(id, owner, session)
	if err != nil {
		return Operation{}, err
	}
	return *r, nil
}

func (o *Operations) getLocked(id string, owner int64, session string) (*Operation, error) {
	o.sweepLocked()
	r := o.records[id]
	if r == nil || r.owner != owner || subtle.ConstantTimeCompare([]byte(r.session), []byte(session)) != 1 {
		return nil, errNoOperation
	}
	return r, nil
}

// Update changes the state of an operation; finished states get the
// download lifetime. It reports false when the operation is gone.
func (o *Operations) Update(id string, status OperationStatus, size int64, summary *Summary, errText string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	r := o.records[id]
	if r == nil {
		return false
	}
	r.Status, r.Error = status, errText
	if size > 0 {
		r.Size = size
	}
	if summary != nil {
		s := *summary
		r.Summary = &s
	}
	if !status.Active() {
		r.expires = o.now().Add(o.ttl)
	}
	return true
}

// ClaimDownload marks a ready backup as downloading: it can be
// downloaded once.
func (o *Operations) ClaimDownload(id string, owner int64, session string) (Operation, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	r, err := o.getLocked(id, owner, session)
	if err != nil {
		return Operation{}, err
	}
	if r.Kind != KindCreated || r.Status != StatusReady {
		return Operation{}, errNoOperation
	}
	if info, err := os.Lstat(r.Archive()); err != nil || !info.Mode().IsRegular() {
		return Operation{}, errNoOperation
	}
	r.Status = StatusDownloading
	return *r, nil
}

// PrepareRestore issues the confirmation token of a verified upload,
// valid for five minutes.
func (o *Operations) PrepareRestore(id string, owner int64, session string) (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	r, err := o.getLocked(id, owner, session)
	if err != nil {
		return "", err
	}
	if r.Kind != KindUploaded || r.Status != StatusVerified {
		return "", errNoOperation
	}
	r.confirm, r.confirmExpires = newToken(), o.now().Add(5*time.Minute)
	return r.confirm, nil
}

// BeginRestore consumes the confirmation token and marks the upload as
// restoring; no other operation may be active.
func (o *Operations) BeginRestore(id string, owner int64, session, token string) (Operation, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	r, err := o.getLocked(id, owner, session)
	if err != nil {
		return Operation{}, err
	}
	if r.Kind != KindUploaded || r.Status != StatusVerified || r.confirm == "" ||
		subtle.ConstantTimeCompare([]byte(r.confirm), []byte(token)) != 1 || !o.now().Before(r.confirmExpires) {
		return Operation{}, errNoOperation
	}
	for _, other := range o.records {
		if other != r && other.Status.Active() {
			return Operation{}, errNoOperation
		}
	}
	r.confirm, r.Status, r.expires = "", StatusRestoring, o.now().Add(o.timeout)
	return *r, nil
}

// ResetUnstartedRestore makes a verified upload retryable after its
// restore could not be started.
func (o *Operations) ResetUnstartedRestore(id string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if r := o.records[id]; r != nil && r.Status == StatusRestoring {
		r.Status, r.Error, r.expires = StatusVerified, "", o.now().Add(o.ttl)
	}
}

// Remove deletes an operation and its files.
func (o *Operations) Remove(id string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.removeLocked(id)
}

func (o *Operations) removeLocked(id string) error {
	r := o.records[id]
	if r == nil {
		return nil
	}
	delete(o.records, id)
	return os.RemoveAll(r.dir)
}

// Sweep removes expired operations that are not active.
func (o *Operations) Sweep() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.sweepLocked()
}

func (o *Operations) sweepLocked() {
	now := o.now()
	for id, r := range o.records {
		if !r.expires.After(now) && !r.Status.Active() {
			_ = o.removeLocked(id)
		}
	}
}

// Close removes every operation (shutdown).
func (o *Operations) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	var errs []error
	for id := range o.records {
		errs = append(errs, o.removeLocked(id))
	}
	return errors.Join(errs...)
}
