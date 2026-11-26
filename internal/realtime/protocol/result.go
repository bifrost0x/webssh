package protocol

import (
	"encoding/json/jsontext"

	"github.com/bifrost0x/webssh/internal/fault"
)

// TypeResult is the message type of every reply to a request.
const TypeResult = "result"

// Result is the payload of a "result" message.
type Result struct {
	OK  bool           `json:"ok"`
	P   jsontext.Value `json:"p,omitzero"`
	Err *Error         `json:"err,omitzero"`
}

// Error is the one error shape on the wire. Code is stable and machine
// readable; Message is safe to show; nothing else from the server leaks.
// Handlers do not build it: they return errors from internal/fault and the
// dispatcher converts them with WireError.
type Error struct {
	Code         fault.Code `json:"code"`
	Message      string     `json:"message,omitzero"`
	RetryAfterMS int64      `json:"retry_after_ms,omitzero"`
}

// WireError converts a handler error into its wire form. Unclassified
// errors become fault.Internal without their text, so the caller must log
// the original error. WireError(nil) is nil.
func WireError(err error) *Error {
	if err == nil {
		return nil
	}
	_, code, message := fault.Status(err)
	e := &Error{Code: code, Message: message}
	if d := fault.RetryAfter(err); d > 0 {
		e.RetryAfterMS = max(d.Milliseconds(), 1)
	}
	return e
}
