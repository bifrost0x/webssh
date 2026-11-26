package sftp

import (
	"context"
	"errors"
	"io/fs"

	pkgsftp "github.com/pkg/sftp"

	"github.com/bifrost0x/webssh/internal/fault"
)

// Safe messages of the backend's own failures. Remote text never reaches a
// message.
const (
	msgInvalidReply   = "The server sent an invalid or oversized reply."
	msgStagingUnsafe  = "Private staging permissions are unavailable."
	msgMemberLimit    = "Directory exceeds configured member limit"
	msgMetadataLimit  = "Directory metadata exceeds configured byte limit"
	msgUnsafeName     = "The directory contains an entry that cannot be processed."
	msgDepthLimit     = "Maximum directory depth exceeded"
	msgSaveUncertain  = "The save result could not be confirmed. Keep your draft and reopen the file before saving again."
	msgOwnerKept      = "The file owner or group cannot be preserved by this save method."
	msgSpecialBits    = "Editing files with special permission bits is not supported."
	msgFileChanged    = "The file changed on the server. Reopen it before saving."
	msgLinkUnresolved = "The link target could not be resolved."
)

// mapErr classifies err. mutation marks a request that changes the server:
// when its reply is lost after it was sent, the outcome is unknown.
func (b *Backend) mapErr(err error, mutation bool) error {
	if err == nil {
		return nil
	}
	if _, ok := fault.From(err); ok {
		return err
	}
	if se, ok := errors.AsType[*statusError](err); ok {
		return statusFault(se.code, err)
	}
	if se, ok := errors.AsType[*pkgsftp.StatusError](err); ok {
		return statusFault(se.Code, err)
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fault.Wrap(fault.FileNotFound, err, "")
	case errors.Is(err, fs.ErrPermission):
		return fault.Wrap(fault.FilePermissionDenied, err, "")
	}
	sent := true
	if te, ok := errors.AsType[*transportError](err); ok {
		sent = te.sent
	}
	if cause := b.r.cause(); cause != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		err = errors.Join(err, cause)
	}
	if mutation && sent {
		return fault.Wrap(fault.OutcomeUnknown, err, "")
	}
	switch {
	case errors.Is(err, context.Canceled):
		return fault.Wrap(fault.FileCancelled, err, "")
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, errStalled):
		return fault.Wrap(fault.FileTimeout, err, "")
	case errors.Is(err, errMalformed):
		return fault.Wrap(fault.OperationFailed, err, msgInvalidReply)
	}
	return fault.Wrap(fault.SourceUnavailable, err, "")
}

func statusFault(code uint32, err error) error {
	switch code {
	case fxNoSuchFile:
		return fault.Wrap(fault.FileNotFound, err, "")
	case fxPermissionDenied:
		return fault.Wrap(fault.FilePermissionDenied, err, "")
	case fxOpUnsupported:
		return fault.Wrap(fault.UnsupportedOperation, err, "")
	}
	return fault.Wrap(fault.OperationFailed, err, "")
}

// answered reports whether the server replied to the request that failed
// with err, so that its outcome is known.
func answered(err error) bool {
	if err == nil {
		return true
	}
	if _, ok := errors.AsType[*statusError](err); ok {
		return true
	}
	if _, ok := errors.AsType[*pkgsftp.StatusError](err); ok {
		return true
	}
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission)
}
