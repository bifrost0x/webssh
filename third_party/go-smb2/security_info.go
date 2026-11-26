package smb2

import (
	"context"
	"os"

	pathpkg "github.com/hirochachacha/go-smb2/v2/internal/path"
	"github.com/hirochachacha/go-smb2/v2/x/protocol"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

// SecurityInfo describes the negotiated security of a session.
type SecurityInfo = protocol.SecurityInfo

// ErrEncryptionUnavailable is returned by Dial when RequireEncryption is set
// and the server did not negotiate a cipher.
var ErrEncryptionUnavailable = protocol.ErrEncryptionUnavailable

// ErrCredentialsRequired is returned by Dial when RequireEncryption is set
// and the credentials authenticate anonymously, for example an
// auth.NTLMCredential with empty User, Password and Hash. No connection is
// opened.
var ErrCredentialsRequired = protocol.ErrCredentialsRequired

// SecurityInfo returns the negotiated dialect, cipher and session flags.
func (c *Session) SecurityInfo() SecurityInfo {
	if c == nil {
		return SecurityInfo{}
	}
	return c.s.SecurityInfo()
}

// ShareInfo describes a mounted tree.
type ShareInfo struct {
	ShareType  uint8
	ShareFlags uint32
	DFS        bool
	Encrypted  bool
}

// Info returns the TREE_CONNECT properties of the share.
func (fs *Share) Info() ShareInfo {
	if fs == nil || fs.treeConn == nil {
		return ShareInfo{}
	}
	tc := fs.treeConn
	return ShareInfo{ShareType: tc.ShareType(), ShareFlags: tc.ShareFlags(), DFS: tc.IsDFS(), Encrypted: tc.Encrypted()}
}

// OpenSpec selects exact CREATE parameters for OpenWith.
type OpenSpec struct {
	DesiredAccess     uint32
	ShareAccess       uint32
	CreateDisposition uint32
	CreateOptions     uint32
	FileAttributes    uint32
}

// OpenWith issues one CREATE with the given parameters and never follows
// symbolic links, in any path component.
func (fs *Share) OpenWith(ctx context.Context, name string, spec OpenSpec) (*File, error) {
	if ctx == nil {
		panic("nil context")
	}
	if fs == nil {
		return nil, os.ErrInvalid
	}
	var err error
	name, err = pathpkg.NormalizeRelPath(pathpkg.ToSMBPath(name))
	if err != nil {
		return nil, err
	}
	req := fs.Request().WithFollowSymlinks(false).Append(&wire.CreateRequest{
		RequestedOplockLevel: wire.SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   wire.Impersonation,
		DesiredAccess:        spec.DesiredAccess,
		FileAttributes:       spec.FileAttributes,
		ShareAccess:          spec.ShareAccess,
		CreateDisposition:    spec.CreateDisposition,
		CreateOptions:        spec.CreateOptions,
		Name:                 name,
		Contexts:             []wire.Encoder{wire.QueryOnDiskIDRequest{}},
	})
	res, err := req.Do(ctx)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	defer res.Close()
	r, err := res.Create(0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	f := fs.newFile(r, name)
	f.readAccess = spec.DesiredAccess&(wire.FILE_READ_DATA|wire.GENERIC_READ|wire.GENERIC_ALL) != 0
	return f, nil
}
