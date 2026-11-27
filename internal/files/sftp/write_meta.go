package sftp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"os"
	"path"

	pkgsftp "github.com/pkg/sftp"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
)

// snapshot is the permission state a replacement keeps (permission_snapshot
// of app/file_mutations.py): type, permission and special bits, size,
// modification time and owner.
type snapshot struct {
	dir      bool
	perm     uint32
	special  uint32
	size     uint64
	mtime    uint32
	owner    bool
	uid, gid uint32
}

func snapshotOf(a attrs) (snapshot, bool) {
	if !a.has(attrPermissions) || !isRegular(a.mode) && !isDir(a.mode) {
		return snapshot{}, false
	}
	return snapshot{
		dir: isDir(a.mode), perm: a.mode & 0o777, special: a.mode & 0o7000,
		size: a.size, mtime: a.mtime, owner: a.has(attrUIDGID), uid: a.uid, gid: a.gid,
	}, true
}

func snapshotOfStat(st *pkgsftp.FileStat) (snapshot, bool) {
	return snapshotOf(attrs{
		flags: attrSize | attrUIDGID | attrPermissions | attrACModTime,
		size:  st.Size, uid: st.UID, gid: st.GID, mode: st.Mode, mtime: st.Mtime,
	})
}

// stagingPath is a hidden sibling of p whose length does not depend on the
// name of p (staging_path of the Python release).
func stagingPath(p, purpose string) string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return path.Join(path.Dir(p), ".webssh-"+purpose+"-"+hex.EncodeToString(b[:])+".tmp")
}

// Failures of the source stream, told apart from those of the server.
var (
	errSourceLimit  = errors.New("source exceeds the limit")
	errSourceLength = errors.New("source length differs from the declared size")
)

// source counts, bounds and hashes the bytes of a write.
type source struct {
	ctx  context.Context
	r    io.Reader
	n    int64
	size int64 // declared length or -1
	max  int64 // 0: no bound
	h    hash.Hash
	err  error // first failure of the stream itself
}

func newSource(ctx context.Context, r io.Reader, o files.WriteOptions) *source {
	return &source{ctx: ctx, r: r, size: o.Size, max: o.MaxBytes, h: sha256.New()}
}

// Size tells pkg/sftp that the length is unknown, so it writes with its
// full concurrency.
func (s *source) Size() int64 { return -1 }

func (s *source) Read(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	if err := s.ctx.Err(); err != nil {
		s.err = err
		return 0, err
	}
	n, err := s.r.Read(p)
	s.n += int64(n)
	s.h.Write(p[:n])
	switch {
	case s.max > 0 && s.n > s.max:
		s.err = errSourceLimit
	case s.size >= 0 && s.n > s.size:
		s.err = errSourceLength
	case errors.Is(err, io.EOF) && s.size >= 0 && s.n != s.size:
		s.err = errSourceLength
	case err != nil && !errors.Is(err, io.EOF):
		s.err = err
	}
	if s.err != nil {
		return n, s.err
	}
	return n, err
}

// fault classifies a failure of the stream; nil when the stream was fine.
func (s *source) fault() error {
	switch {
	case s.err == nil:
		return nil
	case errors.Is(s.err, errSourceLimit):
		return fault.Wrap(fault.LimitExceeded, s.err, "")
	case errors.Is(s.err, context.Canceled):
		return fault.Wrap(fault.FileCancelled, s.err, "")
	case errors.Is(s.err, context.DeadlineExceeded):
		return fault.Wrap(fault.FileTimeout, s.err, "")
	}
	return fault.Wrap(fault.SourceChanged, s.err, "")
}

// revisionOf reads the file at p and returns its revision, or "" when it
// is larger than limit (then it cannot be the revision the editor
// opened).
func (b *Backend) revisionOf(ctx context.Context, p string, limit int64) (string, error) {
	f, err := b.openFile(ctx, p, os.O_RDONLY)
	if err != nil {
		return "", b.mapErr(err, false)
	}
	defer closeFile(f)
	h := sha256.New()
	n, err := await(ctx, func() (int64, error) { return io.Copy(h, io.LimitReader(f, limit+1)) }, nil)
	if err != nil {
		return "", b.mapErr(err, false)
	}
	if n > limit {
		return "", nil
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
