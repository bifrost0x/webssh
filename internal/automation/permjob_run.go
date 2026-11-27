package automation

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
)

// PermRequest is a permission job the page asks for.
type PermRequest struct {
	SourceID  string
	Paths     []string
	Recursive bool
	FileMode  string
	DirMode   string
}

var errJobCancelled = errors.New("automation: permission job cancelled")

// Prepare starts the scan of a new job and returns its state; the page
// polls it until the plan is ready. One active job per user and per source;
// at most PermMaxExecuting scans and applies run at once (BUSY).
func (j *PermissionJobs) Prepare(ctx context.Context, c PermCaller, rq PermRequest) (jsontext.Value, error) {
	if _, err := ParseMode(rq.FileMode); err != nil {
		return nil, err
	}
	if _, err := ParseMode(rq.DirMode); err != nil {
		return nil, err
	}
	roots, err := j.roots(rq.Paths, rq.Recursive)
	if err != nil {
		return nil, err
	}
	_, identity, release, err := j.o.Sources.Hold(ctx, c.P, rq.SourceID)
	if err != nil {
		return nil, err
	}
	release()
	j.mu.Lock()
	defer j.mu.Unlock()
	j.cleanupLocked()
	running := 0
	for _, job := range j.jobs {
		if !active(job.state) {
			continue
		}
		if job.userID == c.P.UserID || job.sourceID == rq.SourceID {
			return nil, fault.New(fault.FileConflict, "")
		}
		if executing(job.state) {
			running++
		}
	}
	if running >= PermMaxExecuting {
		return nil, fault.New(fault.Busy, "")
	}
	now := j.o.Now()
	job := &permJob{id: newJobID(), userID: c.P.UserID, session: c.P.SessionID, peer: c.Peer, sourceID: rq.SourceID,
		identity: identity, recursive: rq.Recursive, fileMode: rq.FileMode, dirMode: rq.DirMode, state: permScanning,
		touched: now, currentFiles: map[string]int{}, currentDirs: map[string]int{}, guards: map[string]permSnapshot{}}
	j.jobs[job.id] = job
	if err := j.startLocked(c, job, PermScanTime, func(ctx context.Context, src PermSource, check func() error) error {
		return j.scan(ctx, job, roots, src, check)
	}); err != nil {
		return nil, err
	}
	return j.publicLocked(job), nil
}

// Apply changes the frozen plan of a ready job. The request carries only
// the job: paths and modes belong to the plan.
func (j *PermissionJobs) Apply(ctx context.Context, c PermCaller, sourceID, id string) (jsontext.Value, error) {
	j.mu.Lock()
	job, err := j.ownedLocked(c, sourceID, id)
	if err == nil && (job.state != permReady || job.cancelled) {
		err = fault.New(fault.FileConflict, "")
	}
	if err == nil && countExecuting(j.jobs) >= PermMaxExecuting {
		err = fault.New(fault.Busy, "")
	}
	identity := any(nil)
	if job != nil {
		identity = job.identity
	}
	j.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if err := j.authorize(ctx, c, sourceID, identity); err != nil {
		return nil, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if job.state != permReady || job.cancelled {
		return nil, fault.New(fault.FileConflict, "")
	}
	job.state, job.touched = permRunning, j.o.Now()
	if err := j.startLocked(c, job, PermApplyTime, func(ctx context.Context, src PermSource, check func() error) error {
		return j.apply(ctx, c, job, src, check)
	}); err != nil {
		return nil, err
	}
	return j.publicLocked(job), nil
}

func countExecuting(jobs map[string]*permJob) int {
	n := 0
	for _, job := range jobs {
		if executing(job.state) {
			n++
		}
	}
	return n
}

// startLocked runs op for job in its own worker with a deadline. The
// worker holds the source, checks the caller's ownership and the source's
// identity before every remote call (check) and records the outcome.
func (j *PermissionJobs) startLocked(c PermCaller, job *permJob, limit time.Duration,
	op func(ctx context.Context, src PermSource, check func() error) error) error {
	fail := func(err error) error {
		job.state, job.code, job.message = permFailed, fault.OperationFailed, "The remote file operation failed."
		job.plan, job.guards, job.touched = nil, nil, j.o.Now()
		return err
	}
	if j.closed || j.o.Draining() {
		return fail(fault.New(fault.OperationFailed, ""))
	}
	releaseQuota := func() {}
	if j.o.Quotas != nil {
		r, err := j.o.Quotas.Reserve(context.Background(), "background_job", c.P.UserID, 1)
		if err != nil {
			return fail(fault.New(fault.OperationFailed, ""))
		}
		releaseQuota = r
	}
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	job.cancel = cancel
	identity := job.identity
	j.wg.Go(func() {
		defer cancel()
		defer releaseQuota()
		check := func() error {
			switch {
			case errors.Is(ctx.Err(), context.DeadlineExceeded):
				return fault.New(fault.FileTimeout, "")
			case ctx.Err() != nil, j.o.Draining():
				return errJobCancelled
			}
			return j.authorize(ctx, c, job.sourceID, identity)
		}
		err := check()
		if err == nil {
			var src PermSource
			var release func()
			src, _, release, err = j.o.Sources.Hold(ctx, c.P, job.sourceID)
			if err == nil {
				err = op(ctx, src, check)
				release()
			}
		}
		if err == nil {
			err = check()
		}
		j.finishJob(c, job, err, ctx)
	})
	return nil
}

func (j *PermissionJobs) finishJob(c PermCaller, job *permJob, err error, ctx context.Context) {
	j.mu.Lock()
	switch {
	case err == nil && job.state == permScanning:
		job.state = permReady
	case err == nil:
		job.state = permCompleted
	case errors.Is(err, errJobCancelled) || job.cancelled && !fault.Is(err, fault.FileTimeout),
		ctx.Err() != nil && !errors.Is(ctx.Err(), context.DeadlineExceeded):
		job.state = permCancelled
	default:
		if errors.Is(ctx.Err(), context.DeadlineExceeded) && fault.CodeOf(err) == "" {
			err = fault.New(fault.FileTimeout, "")
		}
		f := mutationFailure(err, false)
		job.state, job.code = permFailed, fault.CodeOf(f)
		job.message = fileMessage(job.code)
	}
	job.touched = j.o.Now()
	if job.state != permReady {
		job.plan, job.guards = nil, nil
	}
	state := job.state
	j.mu.Unlock()
	j.auditChange(c, job.sourceID, "chmod_job", state, "/", "", "", nil)
}

// fileMessage is the text of app/file_mutations.py for a code.
func fileMessage(c fault.Code) string {
	switch c {
	case fault.InvalidRequest:
		return "Invalid file operation request."
	case fault.FileConflict:
		return "A file or folder with this name already exists."
	case fault.Busy:
		return "Another permission change is still running. Try again in a moment."
	case fault.FilePermissionDenied:
		return "Permission denied for this file operation."
	case fault.FileNotFound:
		return "The file or folder no longer exists."
	case fault.UnsupportedOperation:
		return "This file operation is not supported."
	case fault.MetadataChanged:
		return "The file metadata changed. Reopen the permissions dialog."
	case fault.FileTimeout:
		return "The file operation timed out before it could start."
	case fault.OutcomeUnknown:
		return "The result could not be confirmed. Refresh before taking further action."
	case fault.ModeMismatch:
		return "The server reported different permissions. Refresh and review the current state."
	}
	return "The remote file operation failed."
}

func (j *PermissionJobs) auditChange(c PermCaller, sourceID, operation, result, p, oldMode, newMode string, err error) {
	if j.o.Audit == nil {
		return
	}
	if err != nil {
		result = string(fault.CodeOf(err))
	}
	j.o.Audit.PermissionChange(c.P, sourceID, operation, result, p, oldMode, newMode)
}

// parents of a canonical path, the root first.
func parents(p string) []string {
	var out []string
	for p != "/" {
		p = path.Dir(p)
		out = append(out, p)
	}
	slices.Reverse(out)
	return out
}

func isLink(mode uint32) bool { return mode&0o170000 == 0o120000 }

// guard freezes, or compares, the state of every parent of p.
func (j *PermissionJobs) guard(ctx context.Context, job *permJob, src PermSource, p string, check func() error) error {
	for _, parent := range parents(p) {
		if err := check(); err != nil {
			return err
		}
		e, err := src.Lstat(ctx, parent)
		if err != nil {
			return mutationFailure(err, false)
		}
		s, err := snapshotOf(e)
		if err != nil || !s.Dir {
			return fault.New(fault.MetadataChanged, "")
		}
		j.mu.Lock()
		have, known := job.guards[parent]
		if known && have != s {
			j.mu.Unlock()
			return fault.New(fault.MetadataChanged, "")
		}
		if !known {
			if len(job.guards) >= PermMaxMembers || job.nameBytes+len(parent) > PermMaxNameBytes {
				j.mu.Unlock()
				return fault.New(fault.InvalidRequest, "")
			}
			job.guards[parent] = s
			job.nameBytes += len(parent)
		}
		j.mu.Unlock()
	}
	return nil
}

// current reads the permission state of a planned object; set-id and
// sticky bits are refused.
func current(ctx context.Context, src PermSource, p string) (permSnapshot, error) {
	e, err := src.Lstat(ctx, p)
	if err != nil {
		return permSnapshot{}, mutationFailure(err, false)
	}
	s, err := snapshotOf(e)
	if err != nil {
		return s, err
	}
	if s.Special != 0 {
		return s, fault.New(fault.UnsupportedOperation, "")
	}
	return s, nil
}

func joinChild(dir, name string) (string, bool) {
	if !validLeaf(name) {
		return "", false
	}
	p := path.Join(dir, name)
	return p, len(p) <= permMaxPath && !strings.HasPrefix(p, "//")
}
