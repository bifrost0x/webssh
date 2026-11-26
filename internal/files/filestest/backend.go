// Package filestest provides an in-memory files.Backend for the tests of
// the packages that consume the file contract (files, transfer,
// automation). Only test files import it.
package filestest

import (
	"bytes"
	"context"
	"io"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
)

type node struct {
	dir   bool
	link  string // target of a symbolic link, "" otherwise
	data  []byte
	mode  uint32
	mtime time.Time
}

// Backend is an in-memory source with POSIX semantics. The zero value is
// not usable; call New.
type Backend struct {
	mu     sync.Mutex
	nodes  map[string]*node
	caps   files.Capabilities
	closed bool
	now    func() time.Time

	// Fail, when set, is asked before every operation ("list", "stat",
	// "open", "write", "mkdir", "rename", "remove", "walk", "chmod") and
	// its error is returned instead. It runs with the lock held and must
	// not call the backend.
	Fail func(op, path string) error
}

// New returns an empty source with only the root directory and the
// capabilities of SFTP without chmod.
func New() *Backend {
	t := time.Unix(1_700_000_000, 0).UTC()
	return &Backend{
		nodes: map[string]*node{"/": {dir: true, mode: 0o040755, mtime: t}},
		caps: files.Capabilities{
			Ops: files.CapAll, Replace: []files.Strategy{files.StrategyAtomic},
			SymlinkTargets: true, RootWritable: true,
		},
		now: func() time.Time { return t },
	}
}

// SetCapabilities replaces the capabilities.
func (b *Backend) SetCapabilities(c files.Capabilities) { b.mu.Lock(); b.caps = c; b.mu.Unlock() }

// PutFile stores a regular file, creating missing parents.
func (b *Backend) PutFile(p string, data []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.mkdirAll(path.Dir(p))
	b.nodes[p] = &node{data: bytes.Clone(data), mode: 0o100644, mtime: b.now()}
}

// PutLink stores a symbolic link to target.
func (b *Backend) PutLink(p, target string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.mkdirAll(path.Dir(p))
	b.nodes[p] = &node{link: target, mode: 0o120777, mtime: b.now()}
}

// File returns the content of a regular file.
func (b *Backend) File(p string) ([]byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n, ok := b.nodes[p]
	if !ok || n.dir || n.link != "" {
		return nil, false
	}
	return bytes.Clone(n.data), true
}

func (b *Backend) mkdirAll(p string) {
	for d := p; ; d = path.Dir(d) {
		if _, ok := b.nodes[d]; !ok {
			b.nodes[d] = &node{dir: true, mode: 0o040755, mtime: b.now()}
		}
		if d == "/" {
			return
		}
	}
}

func notFound() error { return fault.New(fault.FileNotFound, "") }

func (b *Backend) begin(ctx context.Context, op, p string) error {
	if err := ctx.Err(); err != nil {
		return fault.Wrap(fault.FileCancelled, err, "")
	}
	if b.closed {
		return fault.New(fault.SourceUnavailable, "")
	}
	if b.Fail != nil {
		return b.Fail(op, p)
	}
	return nil
}

// Capabilities implements files.Backend.
func (b *Backend) Capabilities() files.Capabilities {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.caps
}

// Home implements files.Backend.
func (b *Backend) Home(ctx context.Context) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return "/", b.begin(ctx, "home", "/")
}

func (b *Backend) entry(p string, n *node) files.Entry {
	return files.Entry{
		Name: path.Base(p), Path: p, Size: int64(len(n.data)), Mode: n.mode,
		IsDir: n.dir, IsSymlink: n.link != "", ModTime: n.mtime,
	}
}

// children returns the sorted direct children of dir.
func (b *Backend) children(dir string) []string {
	var out []string
	for p := range b.nodes {
		if p != "/" && path.Dir(p) == dir {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out
}

type listing struct {
	b       *Backend
	entries []files.Entry
	closed  bool
}

// OpenListing implements files.Backend. The entries are fixed when the
// listing opens.
func (b *Backend) OpenListing(ctx context.Context, p string) (files.Listing, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.begin(ctx, "list", p); err != nil {
		return nil, err
	}
	n, ok := b.nodes[p]
	if !ok || !n.dir {
		return nil, notFound()
	}
	l := &listing{b: b}
	for _, c := range b.children(p) {
		l.entries = append(l.entries, b.entry(c, b.nodes[c]))
	}
	return l, nil
}

func (l *listing) Next(ctx context.Context, max int) ([]files.Entry, bool, error) {
	l.b.mu.Lock()
	defer l.b.mu.Unlock()
	if l.closed {
		return nil, false, fault.New(fault.SourceUnavailable, "")
	}
	if err := l.b.begin(ctx, "list", ""); err != nil {
		return nil, false, err
	}
	n := min(max, len(l.entries))
	page := slices.Clone(l.entries[:n])
	l.entries = l.entries[n:]
	return page, len(l.entries) > 0, nil
}

func (l *listing) Close() error { l.closed = true; return nil }

// Stat implements files.Backend.
func (b *Backend) Stat(ctx context.Context, p string, follow bool) (files.Entry, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.begin(ctx, "stat", p); err != nil {
		return files.Entry{}, err
	}
	n, ok := b.nodes[p]
	if ok && follow && n.link != "" {
		p = n.link
		n, ok = b.nodes[p]
	}
	if !ok {
		return files.Entry{}, notFound()
	}
	return b.entry(p, n), nil
}

type reader struct {
	io.Reader
	e files.Entry
}

func (r reader) Close() error       { return nil }
func (r reader) Entry() files.Entry { return r.e }

// Open implements files.Backend.
func (b *Backend) Open(ctx context.Context, p string, r files.Range) (files.Reader, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.begin(ctx, "open", p); err != nil {
		return nil, err
	}
	n, ok := b.nodes[p]
	switch {
	case !ok:
		return nil, notFound()
	case n.dir || n.link != "":
		return nil, fault.New(fault.UnsupportedOperation, "")
	}
	data := n.data[min(max(r.Offset, 0), int64(len(n.data))):]
	if r.Length >= 0 && r.Length < int64(len(data)) {
		data = data[:r.Length]
	}
	return reader{bytes.NewReader(bytes.Clone(data)), b.entry(p, n)}, nil
}

// Write implements files.Backend. It reads src before it changes
// anything, so a failing reader leaves the file as it was.
func (b *Backend) Write(ctx context.Context, p string, src io.Reader, o files.WriteOptions) (files.WriteResult, error) {
	limit := o.MaxBytes
	if limit <= 0 {
		limit = 1 << 40
	}
	data, err := io.ReadAll(io.LimitReader(src, limit+1))
	if err != nil {
		return files.WriteResult{}, fault.Wrap(fault.SourceChanged, err, "")
	}
	if int64(len(data)) > limit {
		return files.WriteResult{}, fault.New(fault.LimitExceeded, "")
	}
	if o.Size >= 0 && o.Size != int64(len(data)) {
		return files.WriteResult{}, fault.New(fault.SourceChanged, "")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.begin(ctx, "write", p); err != nil {
		return files.WriteResult{}, err
	}
	if o.Strategy != "" && !slices.Contains(b.caps.Replace, o.Strategy) {
		return files.WriteResult{}, fault.New(fault.AtomicReplaceUnavailable, "")
	}
	n, exists := b.nodes[p]
	if exists && n.link != "" {
		if !o.FollowSymlink || !b.caps.SymlinkTargets {
			return files.WriteResult{}, fault.New(fault.UnsupportedOperation, "")
		}
		p = n.link
		n, exists = b.nodes[p]
	}
	switch {
	case exists && n.dir:
		return files.WriteResult{}, fault.New(fault.FileConflict, "")
	case exists && o.Exclusive:
		return files.WriteResult{}, fault.New(fault.FileConflict, "")
	case o.ExpectedRevision != "" && (!exists || files.Revision(n.data) != o.ExpectedRevision):
		return files.WriteResult{}, fault.New(fault.EditConflict, "")
	}
	if parent, ok := b.nodes[path.Dir(p)]; !ok || !parent.dir {
		return files.WriteResult{}, notFound()
	}
	mode := uint32(0o100644)
	if exists {
		mode = n.mode
	}
	b.nodes[p] = &node{data: data, mode: mode, mtime: b.now()}
	return files.WriteResult{Revision: files.Revision(data), Size: int64(len(data))}, nil
}

// Mkdir implements files.Backend.
func (b *Backend) Mkdir(ctx context.Context, p string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.begin(ctx, "mkdir", p); err != nil {
		return err
	}
	if _, ok := b.nodes[p]; ok {
		return fault.New(fault.FileConflict, "")
	}
	if parent, ok := b.nodes[path.Dir(p)]; !ok || !parent.dir {
		return notFound()
	}
	b.nodes[p] = &node{dir: true, mode: 0o040755, mtime: b.now()}
	return nil
}

// Rename implements files.Backend.
func (b *Backend) Rename(ctx context.Context, from, to string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.begin(ctx, "rename", from); err != nil {
		return err
	}
	if _, ok := b.nodes[from]; !ok {
		return notFound()
	}
	if _, ok := b.nodes[to]; ok {
		return fault.New(fault.FileConflict, "")
	}
	if files.Within(from, to, b.caps.CaseInsensitive) {
		return fault.New(fault.InvalidRequest, "")
	}
	for p, n := range b.nodes {
		if files.Within(from, p, false) {
			delete(b.nodes, p)
			b.nodes[to+strings.TrimPrefix(p, from)] = n
		}
	}
	return nil
}
