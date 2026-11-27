package smb

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"sync"
	"sync/atomic"
	"time"

	smb2 "github.com/hirochachacha/go-smb2/v2"
	"github.com/hirochachacha/go-smb2/v2/x/protocol"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
)

// Backend is one connected share: a files.Backend. It never reconnects;
// once the session is closed, lost or tainted every operation fails with
// SOURCE_UNAVAILABLE. Operations may run concurrently: the library
// multiplexes requests on the one session within its credits, so
// listings and stats are not held up behind a transfer (decided by
// TestLabOneSessionServesTwoLanes against the two sessions of Python).
type Backend struct {
	session  *smb2.Session
	tree     *smb2.Share
	host     string
	share    string
	ioIdle   time.Duration
	mutation time.Duration
	security smb2.SecurityInfo
	access   files.Access

	dead      atomic.Bool
	closeOnce sync.Once
	closeErr  error

	// hookRename runs before every rename request; tests use it to stall
	// the server at that moment.
	hookRename func()
}

var _ files.Backend = (*Backend)(nil)
var _ files.AccessProber = (*Backend)(nil)

func newBackend(session *smb2.Session, tree *smb2.Share, cfg Config, info smb2.SecurityInfo) *Backend {
	mutation := cfg.MutationTimeout
	if mutation <= 0 {
		mutation = DefaultMutationTimeout
	}
	return &Backend{session: session, tree: tree, ioIdle: cfg.IOIdleTimeout, mutation: mutation, security: info}
}

var errUnavailable = fail(fault.SourceUnavailable, PhaseFileOperation, "SourceClosed", nil)

// alive fails once the source is closed or tainted.
func (b *Backend) alive() error {
	if b.dead.Load() {
		return errUnavailable
	}
	return nil
}

// op bounds one request by the I/O idle timeout.
func (b *Backend) op(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, b.ioIdle)
}

// fileError classifies a failure of a file operation. A broken transport
// ends the source: the session cannot be trusted with another request.
func (b *Backend) fileError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if _, ok := fault.From(err); ok {
		return err
	}
	if _, ok := errors.AsType[*protocol.TransportError](err); ok || errors.Is(err, net.ErrClosed) {
		b.taint()
		return fail(fault.SourceUnavailable, PhaseFileOperation, "TransportError", err)
	}
	return classifyCtx(ctx, err, PhaseFileOperation)
}

// taint ends the session without LOGOFF: after a mutation whose outcome
// is unknown, or a broken transport, no further request may run on it.
func (b *Backend) taint() {
	if b.dead.Swap(true) {
		return
	}
	_ = b.session.Abort()
}

// Close logs off and closes the transport. It is idempotent.
func (b *Backend) Close() error {
	b.closeOnce.Do(func() {
		if b.dead.Swap(true) {
			b.closeErr = b.session.Abort()
			return
		}
		b.closeErr = b.session.Close()
	})
	return b.closeErr
}

// Capabilities: every operation but chmod; replacing an existing file is
// atomic for transfers and a recoverable swap for the editor; names
// compare case-insensitively; the share root cannot be changed.
func (b *Backend) Capabilities() files.Capabilities {
	return files.Capabilities{
		Ops:             files.CapAll,
		Replace:         []files.Strategy{files.StrategyAtomic, files.StrategyRecoverableSwap},
		CaseInsensitive: true,
	}
}

// Home is the share root.
func (b *Backend) Home(context.Context) (string, error) {
	if err := b.alive(); err != nil {
		return "", err
	}
	return "/", nil
}

// Chmod is not offered: SMB has no POSIX permission bits.
func (b *Backend) Chmod(context.Context, string, fs.FileMode) error {
	return fault.New(fault.UnsupportedOperation, "")
}

// Descriptor is the public description of the source. SourceID is set by
// the source registry.
func (b *Backend) Descriptor() files.Descriptor {
	access := b.access
	return files.Descriptor{
		Kind: files.KindSMB, Label: b.share + " on " + b.host, Endpoint: b.host + "/" + b.share,
		Protocol: "SMB 3.1.1", Ephemeral: true,
		Security: files.Security{Encrypted: true, Signed: true, SecureNegotiate: true},
		Access:   &access,
	}
}

// RootAccess is the access probe of the share root made when the source
// was opened (inspect_directory_access).
func (b *Backend) RootAccess() files.Access { return b.access }

// Cipher is the negotiated cipher ID, for diagnostics and tests.
func (b *Backend) Cipher() smb2.Cipher { return b.security.Cipher }

// Access probes the rights of the account in the directory at path
// without changing anything: listing, then creating files, creating
// directories and deleting children.
func (b *Backend) Access(ctx context.Context, p string) (files.Access, error) {
	parts, err := b.parts(p)
	if err != nil {
		return files.Access{}, err
	}
	return b.probe(ctx, parts)
}

func (b *Backend) probe(ctx context.Context, parts []string) (files.Access, error) {
	if err := b.alive(); err != nil {
		return files.Access{}, err
	}
	release, _, err := b.ancestors(ctx, parts, nil)
	if err != nil {
		return files.Access{}, err
	}
	defer release()
	right := func(access uint32) string {
		h, err := b.open(ctx, parts, access|accessAttributes, fileOpen, 0, shareAll, kindDir)
		if err == nil {
			_ = h.close()
			return files.AccessGranted
		}
		if isCode(err, fault.FilePermissionDenied) {
			return files.AccessDenied
		}
		return files.AccessUnknown
	}
	a := files.Access{List: right(accessList)}
	if a.List != files.AccessGranted {
		return a, fail(fault.FilePermissionDenied, PhaseShareAccess, "AccessDenied", nil)
	}
	a.CreateFile = right(fileAddFile)
	a.CreateDirectory = right(fileAddSubdirectory)
	a.DeleteChildren = right(fileDeleteChild)
	return a, nil
}

// parts checks a canonical path against the share component rules.
func (b *Backend) parts(p string) ([]string, error) {
	parts, err := splitPath(p)
	if err != nil {
		return nil, fault.Wrap(fault.InvalidRequest, err, "The path is invalid.")
	}
	return parts, nil
}

// mutable refuses the share root, which cannot be changed.
func (b *Backend) mutable(p string) ([]string, error) {
	parts, err := b.parts(p)
	if err != nil {
		return nil, err
	}
	if len(parts) == 0 {
		return nil, fault.New(fault.InvalidRequest, "The share root cannot be modified.")
	}
	return parts, nil
}
