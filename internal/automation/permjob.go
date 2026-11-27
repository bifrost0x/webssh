package automation

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/jsontext"
	"errors"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/pyjson"
)

// PermOptions are the dependencies of the permission jobs. Sources is
// required.
type PermOptions struct {
	Sources PermSources
	Quotas  PermQuotas // nil reserves nothing
	Audit   PermAudit  // nil records nothing
	// Draining reports that the server takes no new work.
	Draining func() bool
	Now      func() time.Time
}

// Job states as the page shows them.
const (
	permScanning  = "scanning"
	permReady     = "ready"
	permRunning   = "running"
	permCompleted = "completed"
	permCancelled = "cancelled"
	permFailed    = "failed"
)

// PermissionJobs own the reviewed, expiring plans of explicit permission
// changes (app/permission_jobs.py, C-SFTP-07). A job belongs to the user,
// the realtime connection and the source that prepared it. The scan
// freezes every object with its permission state and the state of every
// parent directory; applying changes exactly that plan and stops at the
// first object whose state changed. File and directory modes stay
// separate, links are skipped, set-id and sticky bits are refused, and
// nothing is retried.
type PermissionJobs struct {
	o        PermOptions
	tokenKey []byte

	mu     sync.Mutex
	jobs   map[string]*permJob
	closed bool
	wg     sync.WaitGroup
}

type planItem struct {
	path string
	snap permSnapshot
}

type permJob struct {
	id                   string
	userID               int64
	session              string
	peer                 uint64
	sourceID             string
	identity             any
	recursive            bool
	fileMode, dirMode    string
	state                string
	files, dirs, skipped int
	changed, processed   int
	unchanged, total     int
	nameBytes            int
	touched              time.Time
	code                 fault.Code
	message              string
	currentFiles         map[string]int
	currentDirs          map[string]int
	plan                 []planItem
	guards               map[string]permSnapshot
	cancel               context.CancelFunc // of the running scan or apply
	cancelled            bool
}

// NewPermissionJobs returns the permission jobs.
func NewPermissionJobs(o PermOptions) (*PermissionJobs, error) {
	if o.Sources == nil {
		return nil, errors.New("automation: permission jobs need the file sources")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Draining == nil {
		o.Draining = func() bool { return false }
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return &PermissionJobs{o: o, tokenKey: key, jobs: map[string]*permJob{}}, nil
}

func active(state string) bool {
	return state == permScanning || state == permReady || state == permRunning
}
func executing(state string) bool { return state == permScanning || state == permRunning }

// cleanupLocked expires unused previews and forgets old finished jobs.
func (j *PermissionJobs) cleanupLocked() {
	now := j.o.Now()
	for id, job := range j.jobs {
		switch {
		case job.state == permReady && now.Sub(job.touched) > PermPreviewTTL:
			job.state, job.code = permCancelled, fault.FileExpired
			job.message = "The preview has expired. Start again."
			job.plan, job.guards, job.touched = nil, nil, now
		case !active(job.state) && now.Sub(job.touched) > PermTerminalTTL:
			delete(j.jobs, id)
		}
	}
	var done []*permJob
	for _, job := range j.jobs {
		if !active(job.state) {
			done = append(done, job)
		}
	}
	sort.Slice(done, func(a, b int) bool { return done[a].touched.Before(done[b].touched) })
	for _, job := range done[:max(0, min(len(done), len(j.jobs)-PermMaxRetained))] {
		delete(j.jobs, job.id)
	}
}

func modesJSON(m map[string]int) jsontext.Value {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	members := make([]pyjson.Member, 0, len(keys))
	for _, k := range keys {
		members = append(members, pyjson.Member{Name: k, Value: jsontext.Value(strconv.Itoa(m[k]))})
	}
	return pyjson.Object(members)
}

// publicLocked is the job as the page receives it.
func (j *PermissionJobs) publicLocked(job *permJob) jsontext.Value {
	num := func(n int) jsontext.Value { return jsontext.Value(strconv.Itoa(n)) }
	expires := 0
	if job.state == permReady {
		expires = max(0, int((PermPreviewTTL - j.o.Now().Sub(job.touched)).Seconds()))
	}
	m := []pyjson.Member{
		{Name: "job_id", Value: pyjson.String(job.id)}, {Name: "state", Value: pyjson.String(job.state)},
		{Name: "files", Value: num(job.files)}, {Name: "directories", Value: num(job.dirs)},
		{Name: "skipped", Value: num(job.skipped)}, {Name: "changed", Value: num(job.changed)},
		{Name: "processed", Value: num(job.processed)}, {Name: "unchanged", Value: num(job.unchanged)},
		{Name: "total", Value: num(job.total)}, {Name: "recursive", Value: jsontext.Value(strconv.FormatBool(job.recursive))},
		{Name: "file_mode", Value: pyjson.String(job.fileMode)}, {Name: "directory_mode", Value: pyjson.String(job.dirMode)},
		{Name: "current_modes", Value: pyjson.Object([]pyjson.Member{
			{Name: "files", Value: modesJSON(job.currentFiles)}, {Name: "directories", Value: modesJSON(job.currentDirs)},
		})},
		{Name: "expires_in", Value: num(expires)},
	}
	if job.code != "" {
		m = append(m, pyjson.Member{Name: "code", Value: pyjson.String(string(job.code))},
			pyjson.Member{Name: "error", Value: pyjson.String(job.message)})
	}
	return pyjson.Object(m)
}

func (j *PermissionJobs) ownedLocked(c PermCaller, sourceID, id string) (*permJob, error) {
	j.cleanupLocked()
	job, ok := j.jobs[id]
	if !ok || job.userID != c.P.UserID || job.session != c.P.SessionID || job.peer != c.Peer || job.sourceID != sourceID {
		return nil, fault.New(fault.FileNotFound, "")
	}
	return job, nil
}

// Get returns the state of an owned job.
func (j *PermissionJobs) Get(ctx context.Context, c PermCaller, sourceID, id string) (jsontext.Value, error) {
	if err := j.authorize(ctx, c, sourceID, nil); err != nil {
		return nil, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	job, err := j.ownedLocked(c, sourceID, id)
	if err != nil {
		return nil, err
	}
	return j.publicLocked(job), nil
}

// Cancel stops an owned job. A ready plan is dropped; a running apply
// stops before its next change and keeps what it already changed.
func (j *PermissionJobs) Cancel(ctx context.Context, c PermCaller, sourceID, id string) (jsontext.Value, error) {
	if err := j.authorize(ctx, c, sourceID, nil); err != nil {
		return nil, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	job, err := j.ownedLocked(c, sourceID, id)
	if err != nil {
		return nil, err
	}
	j.cancelLocked(job)
	return j.publicLocked(job), nil
}

func (j *PermissionJobs) cancelLocked(job *permJob) {
	job.cancelled = true
	if job.state == permReady {
		job.state, job.plan, job.guards, job.touched = permCancelled, nil, nil, j.o.Now()
	}
	if job.cancel != nil {
		job.cancel()
	}
}

// PeerClosed stops the jobs of a closed realtime connection.
func (j *PermissionJobs) PeerClosed(userID int64, peer uint64) {
	j.cancelWhere(func(job *permJob) bool { return job.userID == userID && job.peer == peer })
}

// Revoke stops the jobs of an ended session, or of every session of the
// account for an account-wide revocation.
func (j *PermissionJobs) Revoke(rev principal.Revocation) {
	j.cancelWhere(func(job *permJob) bool {
		return job.userID == rev.UserID && (rev.SessionID == "" || job.session == rev.SessionID)
	})
}

func (j *PermissionJobs) cancelWhere(match func(*permJob) bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, job := range j.jobs {
		if active(job.state) && match(job) {
			j.cancelLocked(job)
		}
	}
}

// Shutdown stops every job and waits for the workers until ctx ends.
func (j *PermissionJobs) Shutdown(ctx context.Context) error {
	j.mu.Lock()
	j.closed = true
	for _, job := range j.jobs {
		if active(job.state) {
			j.cancelLocked(job)
		}
	}
	j.mu.Unlock()
	done := make(chan struct{})
	go func() { j.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// authorize checks that the caller still holds the source with chmod;
// with identity it also checks that the source was not opened again.
func (j *PermissionJobs) authorize(ctx context.Context, c PermCaller, sourceID string, identity any) error {
	_, id, release, err := j.o.Sources.Hold(ctx, c.P, sourceID)
	if err != nil {
		return err
	}
	release()
	if identity != nil && id != identity {
		return fault.New(fault.MetadataChanged, "")
	}
	return nil
}

// roots validates the requested paths; a recursive job keeps only the
// topmost of nested roots.
func (j *PermissionJobs) roots(paths []string, recursive bool) ([]string, error) {
	invalid := fault.New(fault.InvalidRequest, "")
	if len(paths) < 1 || len(paths) > PermMaxMembers {
		return nil, invalid
	}
	var out []string
	seen := map[string]bool{}
	names := 0
	for _, raw := range paths {
		p, err := j.o.Sources.Clean(raw)
		if err != nil || !strings.HasPrefix(p, "/") || strings.Count(p, "/") > PermMaxDepth {
			return nil, invalid
		}
		if names += len(p); names > PermMaxNameBytes {
			return nil, invalid
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if !recursive {
		return out, nil
	}
	slices.SortFunc(out, func(a, b string) int { return slices.Compare(strings.Split(a, "/"), strings.Split(b, "/")) })
	var minimal []string
	for _, p := range out {
		if len(minimal) == 0 || !strings.HasPrefix(p, minimal[len(minimal)-1]+"/") {
			minimal = append(minimal, p)
		}
	}
	return minimal, nil
}

func newJobID() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
