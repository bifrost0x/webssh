package smb

import (
	"context"
	"encoding/binary"
	"strings"
	"time"

	smb2 "github.com/hirochachacha/go-smb2/v2"
	"github.com/hirochachacha/go-smb2/v2/x/wire"

	"github.com/bifrost0x/webssh/internal/fault"
)

// Access masks per purpose, those of app/smb_protocol.py.
const (
	accessAttributes     = wire.FILE_READ_ATTRIBUTES
	accessList           = wire.FILE_LIST_DIRECTORY | wire.FILE_READ_ATTRIBUTES
	accessRead           = wire.FILE_READ_DATA | wire.FILE_READ_ATTRIBUTES
	accessDelete         = wire.DELETE | wire.FILE_READ_ATTRIBUTES
	accessDeleteReadOnly = wire.DELETE | wire.FILE_READ_ATTRIBUTES | wire.FILE_WRITE_ATTRIBUTES
	accessCreateMove     = wire.DELETE | wire.FILE_WRITE_DATA | wire.FILE_READ_ATTRIBUTES
	accessFileMove       = wire.DELETE | wire.FILE_READ_DATA | wire.FILE_READ_ATTRIBUTES
	shareAll             = wire.FILE_SHARE_READ | wire.FILE_SHARE_WRITE | wire.FILE_SHARE_DELETE
	shareNoDelete        = wire.FILE_SHARE_READ | wire.FILE_SHARE_WRITE
	shareRead            = wire.FILE_SHARE_READ
	infoBuffer           = 65536

	fileOpen            = wire.FILE_OPEN
	fileCreate          = wire.FILE_CREATE
	fileAddFile         = wire.FILE_ADD_FILE
	fileAddSubdirectory = wire.FILE_ADD_SUBDIRECTORY
	fileDeleteChild     = wire.FILE_DELETE_CHILD
)

const (
	attrReadOnly  = wire.FILE_ATTRIBUTE_READONLY
	attrDirectory = wire.FILE_ATTRIBUTE_DIRECTORY
	attrReparse   = wire.FILE_ATTRIBUTE_REPARSE_POINT
	attrNormal    = wire.FILE_ATTRIBUTE_NORMAL
)

// object is the verified metadata of an open handle or a directory entry.
type object struct {
	Name       string
	ID         uint64 // FileId / IndexNumber, never 0 or all ones
	Attributes uint32
	Size       int64
	ModTime    time.Time
}

func (o object) isDir() bool     { return o.Attributes&attrDirectory != 0 }
func (o object) isReparse() bool { return o.Attributes&attrReparse != 0 }

// validID reports whether a FileId can identify an object.
func validID(id uint64) bool { return id != 0 && id != ^uint64(0) }

type openKind int

const (
	kindAny openKind = iota
	kindFile
	kindDir
)

// handle is one open SMB object with its verified metadata.
type handle struct {
	b    *Backend
	file *smb2.File
	info object
	// bound is the share-relative name the server binds to the handle.
	bound string
}

// open issues one CREATE that never follows a reparse point and checks
// the type and the identity on the returned handle.
func (b *Backend) open(ctx context.Context, parts []string, access, disposition, options, share uint32, kind openKind) (*handle, error) {
	options |= wire.FILE_OPEN_REPARSE_POINT
	switch kind {
	case kindFile:
		options |= wire.FILE_NON_DIRECTORY_FILE
	case kindDir:
		options |= wire.FILE_DIRECTORY_FILE
	}
	opCtx, cancel := b.op(ctx)
	defer cancel()
	f, err := b.tree.OpenWith(opCtx, smbPath(parts), smb2.OpenSpec{
		DesiredAccess: access, ShareAccess: share, CreateDisposition: disposition,
		CreateOptions: options, FileAttributes: wire.FILE_ATTRIBUTE_NORMAL,
	})
	if err != nil {
		return nil, b.fileError(opCtx, err)
	}
	h := &handle{b: b, file: f}
	if err := h.query(opCtx); err != nil {
		_ = h.close()
		return nil, err
	}
	if h.info.isReparse() {
		_ = h.close()
		return nil, fail(fault.SMBReparsePointRejected, PhaseFileOperation, "ReparsePoint", nil)
	}
	return h, nil
}

// query reads basic, standard and internal information and the name in
// one compound request. The name comes from FileNormalizedNameInformation
// ([MS-SMB2] 3.3.5.20.1): Windows Server leaves the name inside
// FileAllInformation empty, so a comparison against it, as the Python
// release made, never matches there.
func (h *handle) query(ctx context.Context) error {
	res, err := h.b.tree.Request().WithFileID(h.file.Fd()).
		QueryInfo(wire.SMB2_0_INFO_FILE, wire.FileAllInformation, 0, infoBuffer).
		QueryInfo(wire.SMB2_0_INFO_FILE, wire.FileNormalizedNameInformation, 0, infoBuffer).Do(ctx)
	if err != nil {
		return h.b.fileError(ctx, err)
	}
	defer res.Close()
	qi, err := res.QueryInfo(0)
	if err != nil {
		return h.b.fileError(ctx, err)
	}
	nqi, err := res.QueryInfo(1)
	if err != nil {
		return h.b.fileError(ctx, err)
	}
	all, name := wire.FileAllInformationDecoder(qi.Output()), wire.FileNameInformationDecoder(nqi.Output())
	if all.IsInvalid() || name.IsInvalid() {
		return opFailed("MalformedInfo")
	}
	basic, standard, internal := all.BasicInformation(), all.StandardInformation(), all.InternalInformation()
	if basic.IsInvalid() || standard.IsInvalid() || internal.IsInvalid() || len(internal) < 8 {
		return opFailed("MalformedInfo")
	}
	// IndexNumber is an opaque 64-bit identifier; read it unsigned.
	id := binary.LittleEndian.Uint64(internal[:8])
	if !validID(id) {
		return fail(fault.SMBIdentityUnavailable, PhaseFileOperation, "IdentityError", nil)
	}
	size := standard.EndOfFile()
	if size < 0 {
		return opFailed("MalformedInfo")
	}
	h.bound = strings.TrimPrefix(name.FileName(), `\`)
	h.info = object{Name: lastComponent(h.bound), ID: id, Attributes: basic.FileAttributes(),
		Size: size, ModTime: basic.LastWriteTime().Time()}
	return nil
}

func lastComponent(p string) string {
	if i := strings.LastIndexByte(p, '\\'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// matches compares the name bound to the handle with parts, folding case
// as the server does. An empty or malformed name never matches.
func (h *handle) matches(parts []string) bool {
	if len(parts) == 0 {
		return h.bound == ""
	}
	got := strings.Split(h.bound, `\`)
	if len(got) != len(parts) {
		return false
	}
	for i, c := range got {
		if c == "" || c == "." || c == ".." || strings.ContainsRune(c, 0) || !strings.EqualFold(c, parts[i]) {
			return false
		}
	}
	return true
}

func (h *handle) setInfo(ctx context.Context, class uint8, input wire.Encoder) error {
	res, err := h.b.tree.Request().WithFileID(h.file.Fd()).SetInfo(wire.SMB2_0_INFO_FILE, class, 0, input).Do(ctx)
	if err != nil {
		return h.b.fileError(ctx, err)
	}
	res.Close()
	return nil
}

// rename moves the object of h to dest without resolving its name again.
func (h *handle) rename(ctx context.Context, dest []string, replace bool) error {
	if len(dest) == 0 {
		return opFailed("InvalidPath")
	}
	if h.b.hookRename != nil {
		h.b.hookRename()
	}
	var flag uint8
	if replace {
		flag = 1
	}
	return h.setInfo(ctx, wire.FileRenameInformation, &wire.FileRenameInformationType2Encoder{ReplaceIfExists: flag, FileName: smbPath(dest)})
}

// markDelete sets the delete disposition; the object goes on close.
func (h *handle) markDelete(ctx context.Context) error {
	return h.setInfo(ctx, wire.FileDispositionInformation, &wire.FileDispositionInformationEncoder{DeletePending: 1})
}

// setAttributes changes only FileAttributes; zero times stay unchanged.
func (h *handle) setAttributes(ctx context.Context, attrs uint32) error {
	return h.setInfo(ctx, wire.FileBasicInformation, &wire.FileBasicInformationEncoder{FileAttributes: attrs})
}

// location returns which of candidates the open handle is bound to now,
// or -1 when it is none of them or the name cannot be read. Reconciling a
// lost reply always goes through the handle, never through a path.
func (h *handle) location(candidates ...[]string) int {
	ctx, cancel := context.WithTimeout(context.Background(), h.b.ioIdle)
	defer cancel()
	if err := h.query(ctx); err != nil {
		return -1
	}
	for i, c := range candidates {
		if h.matches(c) {
			return i
		}
	}
	return -1
}

// close releases the handle with a fresh bounded context, so cleanup runs
// after the caller's context ended too.
func (h *handle) close() error {
	if h == nil || h.file == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), h.b.ioIdle)
	defer cancel()
	err := h.file.Close(ctx)
	h.file = nil
	if err != nil {
		return h.b.fileError(ctx, err)
	}
	return nil
}
