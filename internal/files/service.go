package files

import (
	"context"
	"path"
	"strings"
	"time"

	"github.com/bifrost0x/webssh/internal/principal"
)

// Audit records file source operations (provided by internal/audit).
type Audit interface {
	Security(event string, kv ...any)
}

// Defaults of the file limits (config.py).
const (
	DefaultMaxEditorBytes       = 5 << 20
	DefaultMaxPreviewBytes      = 512000
	DefaultMaxPreviewTailLines  = 10000
	DefaultMaxSupportedFileSize = 1 << 30
	DefaultControlBytesPerMin   = 2 << 20
)

// Options configure a Service; zero values take the defaults of the
// Python release.
type Options struct {
	Registry *Registry
	Audit    Audit // nil records nothing

	PageSize         int           // REMOTE_LISTING_PAGE_SIZE
	SnapshotTTL      time.Duration // REMOTE_LISTING_SNAPSHOT_TTL_SECONDS
	SnapshotsPerUser int           // REMOTE_LISTING_SNAPSHOT_MAX_PER_USER
	SnapshotsTotal   int           // REMOTE_LISTING_SNAPSHOT_MAX_STATES
	MaxMembers       int           // MAX_TRANSFER_MEMBERS

	MaxEditorBytes       int64 // MAX_EDITOR_FILE_SIZE
	EditorBytesPerMinute int64 // EDITOR_SAVE_BYTES_PER_MINUTE
	ControlBytesPerMin   int64 // FILE_CONTROL_BYTES_PER_MINUTE
	MaxPreviewBytes      int64 // MAX_PREVIEW_SIZE
	MaxPreviewTailLines  int64 // MAX_PREVIEW_TAIL_LINES
	MaxSupportedFileSize int64 // MAX_SUPPORTED_FILE_SIZE

	Now func() time.Time
}

func (o *Options) defaults() {
	setInt := func(v *int, d int) {
		if *v <= 0 {
			*v = d
		}
	}
	set64 := func(v *int64, d int64) {
		if *v <= 0 {
			*v = d
		}
	}
	setInt(&o.PageSize, DefaultPageSize)
	setInt(&o.SnapshotsPerUser, DefaultSnapshotsUser)
	setInt(&o.SnapshotsTotal, DefaultSnapshotsGlobal)
	setInt(&o.MaxMembers, DefaultMaxMembers)
	if o.SnapshotTTL <= 0 {
		o.SnapshotTTL = DefaultSnapshotTTL
	}
	set64(&o.MaxEditorBytes, DefaultMaxEditorBytes)
	set64(&o.EditorBytesPerMinute, 4*o.MaxEditorBytes)
	set64(&o.ControlBytesPerMin, DefaultControlBytesPerMin)
	set64(&o.MaxPreviewBytes, DefaultMaxPreviewBytes)
	set64(&o.MaxPreviewTailLines, DefaultMaxPreviewTailLines)
	set64(&o.MaxSupportedFileSize, DefaultMaxSupportedFileSize)
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Registry == nil {
		o.Registry = NewRegistry(RegistryOptions{Now: o.Now})
	}
}

// Service is the file workspace: listings, preview, editor and the
// explicit mutations on the sources of the registry. Every operation
// resolves its source for the caller and the capability it needs first.
type Service struct {
	opts       Options
	reg        *Registry
	list       *listings
	control    *byteBudget
	editor     *byteBudget
	challenges *challenges
}

// New returns a Service. It drops the listings of a source when the
// registry closes it.
func New(o Options) *Service {
	o.defaults()
	s := &Service{
		opts: o, reg: o.Registry, list: newListings(o),
		control: newByteBudget(o.ControlBytesPerMin, o.Now), editor: newByteBudget(o.EditorBytesPerMinute, o.Now),
		challenges: newChallenges(o.Now),
	}
	s.reg.OnClose(func(session, sourceID string) {
		s.list.discard(func(sn *snapshot) bool { return sn.owner.session == session && sn.sourceID == sourceID })
	})
	return s
}

// Registry returns the source registry of the service.
func (s *Service) Registry() *Registry { return s.reg }

// MaxEditorBytes is MAX_EDITOR_FILE_SIZE as the service applies it.
func (s *Service) MaxEditorBytes() int64 { return s.opts.MaxEditorBytes }

// Caller identifies who asks: the principal and its realtime connection.
type Caller struct {
	P    principal.Principal
	Peer uint64
}

func (c Caller) owner() owner { return owner{c.P.UserID, c.P.SessionID, c.Peer} }

// ChargeRequest takes n bytes of a file request from the caller's budget
// (at least 256, as in Python).
func (s *Service) ChargeRequest(c Caller, n int) error {
	return s.control.charge(c.P.UserID, int64(max(n, 256)))
}

// PeerClosed drops the listings of a closed realtime connection and
// closes the quick sources when it was the user's last one.
func (s *Service) PeerClosed(c Caller) {
	o := c.owner()
	s.list.discard(func(sn *snapshot) bool { return sn.owner == o })
	s.reg.PeerClosed(c.P.UserID, c.Peer)
}

// resolved is an owned source held for one operation.
type resolved struct {
	b       Backend
	desc    Descriptor
	caps    Capabilities
	release func()
}

func (s *Service) resolve(ctx context.Context, c Caller, sourceID string, need Capability) (resolved, error) {
	b, release, err := s.reg.Resolve(ctx, c.P, sourceID, need)
	if err != nil {
		return resolved{}, err
	}
	d, caps, err := s.reg.Describe(c.P, sourceID)
	if err != nil {
		release()
		return resolved{}, err
	}
	return resolved{b: b, desc: d, caps: caps, release: release}, nil
}

// audit records one operation as FILE_SOURCE_OPERATION with the target
// fields of the Python release; credentials and paths never appear, only
// the last path element.
func (s *Service) audit(c Caller, r resolved, operation string, err error, file string, size int64, extra ...any) {
	if s.opts.Audit == nil {
		return
	}
	result := "COMPLETED"
	if err != nil {
		result = "FAILED"
	}
	s.auditResult(c, r, operation, result, file, size, extra...)
}

func (s *Service) auditResult(c Caller, r resolved, operation, result, file string, size int64, extra ...any) {
	if s.opts.Audit == nil {
		return
	}
	kind, host, share := "sftp", r.desc.Endpoint, any(nil)
	if r.desc.Kind == KindSMB {
		kind = "smb"
		if i := strings.LastIndexByte(r.desc.Endpoint, '/'); i > 0 {
			host, share = r.desc.Endpoint[:i], r.desc.Endpoint[i+1:]
		}
	}
	kv := []any{
		"user", c.P.Username, "operation", operation, "result", result, "source_kind", kind,
		"target_host", host, "share", share, "filename", baseName(file), "size", size,
	}
	s.opts.Audit.Security("FILE_SOURCE_OPERATION", append(kv, extra...)...)
}

func baseName(p string) string {
	if b := path.Base(strings.TrimRight(p, "/")); b != "." && b != "" {
		return b
	}
	return "/"
}
