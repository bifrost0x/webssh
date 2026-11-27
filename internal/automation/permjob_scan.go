package automation

import (
	"context"
	"slices"
	"strings"

	"github.com/bifrost0x/webssh/internal/fault"
)

type pendingPath struct {
	path  string
	depth int
}

// scan freezes the plan: every root and, for a recursive job, everything
// below it, depth first, with the state of every object and parent. Links
// are counted and skipped, never entered.
func (j *PermissionJobs) scan(ctx context.Context, job *permJob, roots []string, src PermSource, check func() error) error {
	invalid := fault.New(fault.InvalidRequest, "")
	names := 0
	for _, r := range roots {
		names += len(r)
	}
	members := 0
	visited := map[string]bool{}
	pending := make([]pendingPath, 0, len(roots))
	for _, r := range slices.Backward(roots) {
		pending = append(pending, pendingPath{r, 0})
	}
	for len(pending) > 0 {
		if err := check(); err != nil {
			return err
		}
		next := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if visited[next.path] {
			continue
		}
		if next.depth > PermMaxDepth {
			return invalid
		}
		visited[next.path] = true
		if members++; members > PermMaxMembers || names > PermMaxNameBytes {
			return invalid
		}
		if err := j.guard(ctx, job, src, next.path, check); err != nil {
			return err
		}
		if err := check(); err != nil {
			return err
		}
		e, err := src.Lstat(ctx, next.path)
		if err != nil {
			return mutationFailure(err, false)
		}
		if isLink(e.Mode) {
			j.mu.Lock()
			job.skipped++
			j.mu.Unlock()
			continue
		}
		snap, err := snapshotOf(e)
		if err != nil {
			return err
		}
		if snap.Special != 0 {
			return fault.New(fault.UnsupportedOperation, "")
		}
		j.mu.Lock()
		job.nameBytes += len(next.path)
		if job.nameBytes > PermMaxNameBytes {
			j.mu.Unlock()
			return invalid
		}
		job.plan = append(job.plan, planItem{next.path, snap})
		if snap.Dir {
			job.dirs++
			job.currentDirs[snap.Mode]++
		} else {
			job.files++
			job.currentFiles[snap.Mode]++
		}
		job.total = job.files + job.dirs
		if snap.Dir && job.recursive {
			if _, ok := job.guards[next.path]; !ok {
				job.guards[next.path] = snap
			}
		}
		j.mu.Unlock()
		if !snap.Dir || !job.recursive {
			continue
		}
		if err := j.guard(ctx, job, src, next.path, check); err != nil {
			return err
		}
		if err := check(); err != nil {
			return err
		}
		err = src.Children(ctx, next.path, func(name string) error {
			if err := check(); err != nil {
				return err
			}
			child, ok := joinChild(next.path, name)
			if !ok || len(pending)+members >= PermMaxMembers {
				return invalid
			}
			if names += len(child); names > PermMaxNameBytes {
				return invalid
			}
			pending = append(pending, pendingPath{child, next.depth + 1})
			return nil
		})
		if err != nil {
			return mutationFailure(err, false)
		}
	}
	if err := j.preflight(ctx, job, src, check); err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	// Files first, then directories from the deepest up, so a directory
	// stays enterable until everything below it is done.
	slices.SortStableFunc(job.plan, func(a, b planItem) int {
		if a.snap.Dir != b.snap.Dir {
			if a.snap.Dir {
				return 1
			}
			return -1
		}
		if a.snap.Dir {
			if da, db := strings.Count(a.path, "/"), strings.Count(b.path, "/"); da != db {
				return db - da
			}
		}
		return strings.Compare(a.path, b.path)
	})
	return nil
}

// preflight compares every frozen parent and object with the server.
func (j *PermissionJobs) preflight(ctx context.Context, job *permJob, src PermSource, check func() error) error {
	j.mu.Lock()
	guards := make(map[string]permSnapshot, len(job.guards))
	for k, v := range job.guards {
		guards[k] = v
	}
	plan := slices.Clone(job.plan)
	j.mu.Unlock()
	changed := fault.New(fault.MetadataChanged, "")
	for p, want := range guards {
		if err := check(); err != nil {
			return err
		}
		e, err := src.Lstat(ctx, p)
		if err != nil {
			return mutationFailure(err, false)
		}
		if s, err := snapshotOf(e); err != nil || s != want {
			return changed
		}
	}
	for _, item := range plan {
		if err := j.guard(ctx, job, src, item.path, check); err != nil {
			return err
		}
		if err := check(); err != nil {
			return err
		}
		s, err := current(ctx, src, item.path)
		if err != nil {
			return err
		}
		if s != item.snap {
			return changed
		}
	}
	return nil
}

// apply changes the plan object by object and stops at the first object
// whose state differs from the plan. Changes already made remain.
func (j *PermissionJobs) apply(ctx context.Context, c PermCaller, job *permJob, src PermSource, check func() error) error {
	if err := j.preflight(ctx, job, src, check); err != nil {
		return err
	}
	j.mu.Lock()
	plan := slices.Clone(job.plan)
	j.mu.Unlock()
	for _, item := range plan {
		if err := j.guard(ctx, job, src, item.path, check); err != nil {
			return err
		}
		if err := check(); err != nil {
			return err
		}
		s, err := current(ctx, src, item.path)
		if err != nil {
			return err
		}
		if s != item.snap {
			return fault.New(fault.MetadataChanged, "")
		}
		mode := job.fileMode
		if s.Dir {
			mode = job.dirMode
		}
		if mode == s.Mode {
			j.mu.Lock()
			job.processed++
			job.unchanged++
			j.mu.Unlock()
			continue
		}
		if err := check(); err != nil {
			return err
		}
		perm, _ := ParseMode(mode)
		if err := src.Chmod(ctx, item.path, perm); err != nil {
			return mutationFailure(err, true)
		}
		after, err := current(ctx, src, item.path)
		if err != nil {
			return fault.New(fault.OutcomeUnknown, "")
		}
		want := item.snap
		want.Mode = mode
		if after != want {
			return fault.New(fault.OutcomeUnknown, "")
		}
		j.mu.Lock()
		job.changed++
		job.processed++
		if _, ok := job.guards[item.path]; ok {
			job.guards[item.path] = after
		}
		j.mu.Unlock()
		j.auditChange(c, job.sourceID, "chmod", "COMPLETED", item.path, s.Mode, mode, nil)
	}
	return nil
}
