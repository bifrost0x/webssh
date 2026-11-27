package smb

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"

	smb2 "github.com/hirochachacha/go-smb2/v2"
	"github.com/hirochachacha/go-smb2/v2/x/protocol"

	"github.com/bifrost0x/webssh/internal/fault"
)

// Phase is the diagnostic phase of a failure (SMB_DIAGNOSTIC_PHASES of
// app/smb_diagnostics.py).
type Phase string

// Diagnostic phases, spelled as in the Python release.
const (
	PhaseFileOperation         Phase = "file_operation"
	PhaseLifecycle             Phase = "lifecycle"
	PhaseSecurityRequirements  Phase = "security_requirements"
	PhaseSessionAuthentication Phase = "session_authentication"
	PhaseShareAccess           Phase = "share_access"
	PhaseTargetResolution      Phase = "target_resolution"
	PhaseTransportNegotiate    Phase = "transport_negotiate"
	PhaseUnknown               Phase = "unknown"
)

// NTSTATUS values of [MS-ERREF] 2.3.1 that the mapping names.
const (
	statusLogonFailure          uint32 = 0xC000006D
	statusWrongPassword         uint32 = 0xC000006A
	statusPasswordExpired       uint32 = 0xC0000071
	statusAccountRestriction    uint32 = 0xC000006E
	statusAccountDisabled       uint32 = 0xC0000072
	statusAccessDenied          uint32 = 0xC0000022
	statusPrivilegeNotHeld      uint32 = 0xC0000061
	statusNetworkAccessDenied   uint32 = 0xC00000CA
	statusMediaWriteProtected   uint32 = 0xC00000A2
	statusObjectNameNotFound    uint32 = 0xC0000034
	statusObjectPathNotFound    uint32 = 0xC000003A
	statusNotFound              uint32 = 0xC0000225
	statusNoSuchFile            uint32 = 0xC000000F
	statusObjectNameInvalid     uint32 = 0xC0000033
	statusBadNetworkName        uint32 = 0xC00000CC
	statusObjectNameCollision   uint32 = 0xC0000035
	statusSharingViolation      uint32 = 0xC0000043
	statusDirectoryNotEmpty     uint32 = 0xC0000101
	statusFileIsADirectory      uint32 = 0xC00000BA
	statusNotADirectory         uint32 = 0xC0000103
	statusDeletePending         uint32 = 0xC0000056
	statusCannotDelete          uint32 = 0xC0000121
	statusIOTimeout             uint32 = 0xC00000B5
	statusStoppedOnSymlink      uint32 = 0x8000002D
	statusFileClosed            uint32 = 0xC0000128
	statusNetworkNameDeleted    uint32 = 0xC00000C9
	statusUserSessionDeleted    uint32 = 0xC0000203
	statusInvalidInfoClass      uint32 = 0xC0000003
	statusNotSupported          uint32 = 0xC00000BB
	statusInvalidDeviceRequest  uint32 = 0xC0000010
	statusInsufficientResources uint32 = 0xC000009A
)

// pythonStatusCodes is _mapped_protocol_error of app/smb_protocol.py for
// SMBOSError and the smbprotocol exception classes (vectors in
// testdata/python_vectors.json).
var pythonStatusCodes = map[uint32]fault.Code{
	statusLogonFailure:        fault.SMBAuthenticationRequired,
	statusWrongPassword:       fault.SMBAuthenticationRequired,
	statusPasswordExpired:     fault.SMBAuthenticationRequired,
	statusAccessDenied:        fault.FilePermissionDenied,
	statusPrivilegeNotHeld:    fault.FilePermissionDenied,
	statusObjectNameNotFound:  fault.FileNotFound,
	statusObjectPathNotFound:  fault.FileNotFound,
	statusNotFound:            fault.FileNotFound,
	statusBadNetworkName:      fault.ShareUnavailable,
	statusObjectNameCollision: fault.FileConflict,
	statusSharingViolation:    fault.FileConflict,
	statusDirectoryNotEmpty:   fault.FileConflict,
	statusFileIsADirectory:    fault.FileConflict,
	statusNotADirectory:       fault.FileConflict,
}

// extraStatusCodes are statuses the Python release reported as
// OPERATION_FAILED although their meaning is clear (fix): a disabled
// account, a write-protected share, a vanished name, a pending delete, a
// closed session, a reparse point the server stopped on and a server-side
// I/O timeout (Python mapped the latter only for its own exception class).
var extraStatusCodes = map[uint32]fault.Code{
	statusIOTimeout:            fault.FileTimeout,
	statusAccountRestriction:   fault.SMBAuthenticationRequired,
	statusAccountDisabled:      fault.SMBAuthenticationRequired,
	statusNetworkAccessDenied:  fault.FilePermissionDenied,
	statusMediaWriteProtected:  fault.FilePermissionDenied,
	statusNoSuchFile:           fault.FileNotFound,
	statusObjectNameInvalid:    fault.FileNotFound,
	statusDeletePending:        fault.FileConflict,
	statusStoppedOnSymlink:     fault.SMBReparsePointRejected,
	statusFileClosed:           fault.SourceUnavailable,
	statusNetworkNameDeleted:   fault.SourceUnavailable,
	statusUserSessionDeleted:   fault.SourceUnavailable,
	statusInvalidInfoClass:     fault.SMBOperationUnavailable,
	statusNotSupported:         fault.SMBOperationUnavailable,
	statusInvalidDeviceRequest: fault.SMBOperationUnavailable,
}

// StatusCode maps an NTSTATUS to the public code.
func StatusCode(status uint32) fault.Code {
	if c, ok := pythonStatusCodes[status]; ok {
		return c
	}
	if c, ok := extraStatusCodes[status]; ok {
		return c
	}
	return fault.OperationFailed
}

// diagnostic is the cause of every SMB *fault.Error: credential-free
// facts for the server log (build_smb_diagnostic). It never reaches a
// client.
type diagnostic struct {
	phase  Phase
	status uint32 // 0: no NTSTATUS
	cause  string // fixed type name, never remote text
	err    error
}

func (d *diagnostic) Error() string {
	if d.status != 0 {
		return fmt.Sprintf("smb %s %s (0x%08X)", d.phase, d.cause, d.status)
	}
	return fmt.Sprintf("smb %s %s", d.phase, d.cause)
}

func (d *diagnostic) Unwrap() error { return d.err }

// Diagnostic is what the server log records about a failure: the phase,
// the cause type and the NTSTATUS in the 0x%08X form of the Python
// release ("" when there was none).
type Diagnostic struct {
	Phase    Phase
	Cause    string
	NtStatus string
}

// DiagnosticOf returns the diagnostic of an SMB failure; other errors
// have the phase "unknown".
func DiagnosticOf(err error) Diagnostic {
	d, ok := errors.AsType[*diagnostic](err)
	if !ok {
		return Diagnostic{Phase: PhaseUnknown}
	}
	out := Diagnostic{Phase: d.phase, Cause: d.cause}
	if d.status != 0 {
		out.NtStatus = fmt.Sprintf("0x%08X", d.status)
	}
	return out
}

// fail builds a classified SMB failure. The message is the default text
// of the code.
func fail(code fault.Code, phase Phase, cause string, err error) *fault.Error {
	return fault.Wrap(code, &diagnostic{phase: phase, cause: cause, err: err}, "")
}

// classify maps an error of the library or the transport to a classified
// failure. A *fault.Error passes unchanged.
func classify(err error, phase Phase) error {
	if err == nil {
		return nil
	}
	if fe, ok := fault.From(err); ok {
		return fe
	}
	if re, ok := errors.AsType[*protocol.ResponseError](err); ok {
		e := fail(StatusCode(re.Code), phase, "ResponseError", err)
		e.Err.(*diagnostic).status = re.Code
		return e
	}
	connect := phase != PhaseFileOperation
	switch {
	case errors.Is(err, context.Canceled):
		if connect {
			return fail(fault.SMBConnectCancelled, phase, "Canceled", err)
		}
		return fail(fault.FileCancelled, phase, "Canceled", err)
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return fail(fault.FileTimeout, phase, "DeadlineExceeded", err)
	case errors.Is(err, smb2.ErrEncryptionUnavailable):
		return fail(fault.SMBEncryptionRequired, PhaseSecurityRequirements, "EncryptionUnavailable", err)
	case errors.Is(err, smb2.ErrCredentialsRequired):
		return fail(fault.SMBAuthenticationRequired, PhaseSessionAuthentication, "CredentialsRequired", err)
	}
	if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
		return fail(fault.FileTimeout, phase, "NetTimeout", err)
	}
	if connect {
		return fail(fault.SMBConnectionFailed, phase, "ConnectionError", err)
	}
	return fail(fault.OperationFailed, phase, "ProtocolError", err)
}

// classifyCtx prefers the caller's cancellation or deadline over the
// transport error the aborted request surfaced.
func classifyCtx(ctx context.Context, err error, phase Phase) error {
	if err == nil {
		return nil
	}
	if _, ok := fault.From(err); ok {
		return err
	}
	switch cerr := ctx.Err(); {
	case errors.Is(cerr, context.DeadlineExceeded):
		return fail(fault.FileTimeout, phase, "DeadlineExceeded", errors.Join(cerr, err))
	case cerr != nil && phase == PhaseFileOperation:
		return fail(fault.FileCancelled, phase, "Canceled", errors.Join(cerr, err))
	case cerr != nil:
		return fail(fault.SMBConnectCancelled, phase, "Canceled", errors.Join(cerr, err))
	}
	return classify(err, phase)
}

// isCode reports whether err carries code.
func isCode(err error, code fault.Code) bool {
	fe, ok := fault.From(err)
	return ok && fe.Code == code
}

// opFailed is the failure of a malformed reply or an invariant the
// server broke.
func opFailed(cause string) *fault.Error {
	return fail(fault.OperationFailed, PhaseFileOperation, cause, nil)
}
