package client

import (
	"context"
	"errors"
	"net"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/fault"
)

// HopError says which hop a failure belongs to. It is the cause of the
// *fault.Error the dialer returns, so the terminal reads the prompt context
// with errors.As. Detail is a finer stable code where the Python release
// had one (the socks_* codes); it is empty otherwise.
//
// Error() of a HopError, like that of the fault.Error around it, includes
// causes with remote-supplied text. It is for logs only; what a client
// sees comes from fault.Status (enforced by internal/architecture).
type HopError struct {
	Role   Role
	Detail string
	Err    error
}

func (e *HopError) Error() string {
	s := string(e.Role)
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

// Unwrap returns the cause.
func (e *HopError) Unwrap() error { return e.Err }

// Sentinels of the authentication plan.
var (
	errAuthExhausted = errors.New("no authentication method left")
	errInteraction   = errors.New("interactive answer required")
	errMultiStep     = errors.New("multi-step keyboard-interactive prompt")
	errBanner        = errors.New("banner declined")
)

// fail classifies a failure of one hop. Faults raised by our own checks
// (network policy, host keys, keys) keep their code and safe message;
// transport errors are mapped to stable codes. Remote-supplied text never
// reaches the message.
func fail(ctx context.Context, role Role, timedOut bool, err error) error {
	if _, ok := errors.AsType[*HopError](err); ok {
		return err
	}
	code, message, detail := classify(ctx, timedOut, err)
	return fault.Wrap(code, &HopError{Role: role, Detail: detail, Err: err}, message)
}

func classify(ctx context.Context, timedOut bool, err error) (fault.Code, string, string) {
	if se, ok := errors.AsType[*SOCKSError](err); ok {
		return se.fault(), "", se.Code
	}
	switch {
	case errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled):
		return fault.Cancelled, "", ""
	case timedOut || errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded):
		return fault.Timeout, "", ""
	}
	if fe, ok := fault.From(err); ok && fe.Code.Known() {
		return fe.Code, fe.Message, ""
	}
	switch {
	case errors.Is(err, errBanner):
		return fault.BannerDeclined, "", ""
	case errors.Is(err, errMultiStep):
		return fault.NotAvailableInPreview, "The host asks for further input (for example a one-time code). Interactive sign-in is not available in this preview.", ""
	case errors.Is(err, errInteraction):
		return fault.InteractionRequired, "", ""
	case errors.Is(err, errAuthExhausted):
		return fault.AuthFailed, "", ""
	}
	if _, ok := errors.AsType[*ssh.AlgorithmNegotiationError](err); ok {
		return fault.NoCommonAlgorithm, "", ""
	}
	if _, ok := errors.AsType[*ssh.OpenChannelError](err); ok {
		return fault.ChannelRejected, "", ""
	}
	if op, ok := errors.AsType[*net.OpError](err); ok && op.Op == "dial" {
		return fault.Unreachable, "", ""
	}
	return fault.SSHProtocol, "", ""
}
