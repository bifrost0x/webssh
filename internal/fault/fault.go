// Package fault is the one error model of the Go backend. Every failure
// that leaves a capability for a transport carries a stable Code from the
// catalog and, optionally, a message that is safe to show. The transports
// (internal/httpapi, internal/realtime) map errors with Status and never
// send the text of an unclassified error: those become Internal, and the
// cause is logged by the transport.
//
// The package uses only the standard library and does not import net/http,
// so foundation and capability packages can use it anywhere (ADR 0003).
package fault

import (
	"errors"
	"time"
)

// Error is a classified failure.
//
// Message is shown to the user as is; it must never contain secrets,
// remote-supplied text, paths or internal identifiers. Err is the cause
// for logs; it is never sent to a client.
type Error struct {
	Code    Code
	Message string
	// RetryAfter tells the client when to retry (RateLimited, Busy).
	RetryAfter time.Duration
	// Details are facts the page acts on (requires_confirmation, usages);
	// optional, JSON-encodable and as safe to show as Message. The
	// realtime transport sends them as err.details.
	Details map[string]any
	Err     error
}

// Error returns a text for logs: code, message and cause.
func (e *Error) Error() string {
	s := string(e.Code)
	if e.Message != "" {
		s += ": " + e.Message
	}
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

// Unwrap returns the cause.
func (e *Error) Unwrap() error { return e.Err }

// Is reports whether target is a *Error with the same code, so that
// errors.Is(err, fault.New(fault.NotFound, "")) matches by code.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

// New returns a classified error with a safe message; an empty message
// uses the code's default text.
func New(code Code, message string) *Error {
	return &Error{Code: code, Message: message}
}

// Wrap classifies cause. The message must be safe to show; cause is kept
// for logs only.
func Wrap(code Code, cause error, message string) *Error {
	return &Error{Code: code, Message: message, Err: cause}
}

// From returns the first *Error in err's chain.
func From(err error) (*Error, bool) {
	return errors.AsType[*Error](err)
}

// CodeOf returns the code of err: "" for nil, Internal for an unclassified
// error.
func CodeOf(err error) Code {
	if err == nil {
		return ""
	}
	if fe, ok := From(err); ok && fe.Code.Known() {
		return fe.Code
	}
	return Internal
}

// Is reports whether err carries code.
func Is(err error, code Code) bool {
	return err != nil && CodeOf(err) == code
}

// Status maps err to what a transport may send: the HTTP status, the code
// and a safe message. An unclassified error, or one with a code outside
// the catalog, becomes Internal with the default message, so internal text
// never reaches a client. Status(nil) returns 200 and no code.
func Status(err error) (httpStatus int, code Code, message string) {
	if err == nil {
		return 200, "", ""
	}
	fe, ok := From(err)
	if !ok || !fe.Code.Known() {
		return Internal.HTTPStatus(), Internal, Internal.DefaultMessage()
	}
	message = fe.Message
	if message == "" {
		message = fe.Code.DefaultMessage()
	}
	return fe.Code.HTTPStatus(), fe.Code, message
}

// DetailsOf returns the details of err, or nil. Like Status it gives
// nothing for an unclassified error or a code outside the catalog.
func DetailsOf(err error) map[string]any {
	if fe, ok := From(err); ok && fe.Code.Known() {
		return fe.Details
	}
	return nil
}

// RetryAfter returns the retry hint of err, or 0.
func RetryAfter(err error) time.Duration {
	if fe, ok := From(err); ok {
		return fe.RetryAfter
	}
	return 0
}
