package transfer

import (
	"context"
	"errors"

	"github.com/bifrost0x/webssh/internal/fault"
)

// operation names the kind of transfer a failure belongs to; it chooses
// the text of a permission failure (app/transfer_errors.py).
type operation string

const (
	opUpload   operation = "upload"
	opDownload operation = "download"
	opFolder   operation = "folder_download"
	opCopy     operation = "remote_transfer"
)

// publicCodes are the codes a transfer reports; every other failure is
// TRANSFER_UNAVAILABLE, so no backend detail reaches the page.
var publicMessages = map[fault.Code]string{
	fault.FileConflict:             "A file or folder already exists at the destination.",
	fault.FileNotFound:             "The requested file or folder was not found.",
	fault.ShareUnavailable:         "The SMB share is unavailable.",
	fault.FileTimeout:              "The file operation timed out.",
	fault.SourceUnavailable:        "The file source is no longer available. Reconnect and try again.",
	fault.SourceChanged:            "The source changed during the transfer. Try again.",
	fault.LimitExceeded:            "The transfer exceeds the configured limit.",
	fault.FileCancelled:            "The transfer was cancelled.",
	fault.AtomicReplaceUnavailable: "Safe overwrite is unavailable for this destination.",
	fault.TransferUnavailable:      "The transfer could not be completed.",
	fault.FilePermissionDenied:     "Permission denied for this file operation.",
}

func permissionMessage(op operation) string {
	switch op {
	case opUpload:
		return "No write permission for the destination."
	case opDownload, opFolder:
		return "No read permission for the source."
	}
	return publicMessages[fault.FilePermissionDenied]
}

// failureOf classifies err for the page. A context error counts as a
// cancellation, except a deadline, which is a timeout.
func failureOf(err error, op operation) Failure {
	code := fault.TransferUnavailable
	switch fe, ok := fault.From(err); {
	case ok:
		if _, public := publicMessages[fe.Code]; public {
			code = fe.Code
		}
	case errors.Is(err, context.DeadlineExceeded):
		code = fault.FileTimeout
	case errors.Is(err, context.Canceled):
		code = fault.FileCancelled
	}
	return newFailure(code, op)
}

func newFailure(code fault.Code, op operation) Failure {
	msg := publicMessages[code]
	if code == fault.FilePermissionDenied {
		msg = permissionMessage(op)
	}
	return Failure{Code: code, Message: msg}
}

// limitFailure is LIMIT_EXCEEDED with the limit the page can explain.
func limitFailure(kind LimitKind, limit, actual int64) Failure {
	f := newFailure(fault.LimitExceeded, "")
	f.LimitKind, f.LimitBytes, f.ActualBytes = kind, limit, actual
	return f
}

// text is the message of f, or the default text of its code.
func (f Failure) text() string {
	if f.Message != "" {
		return f.Message
	}
	return publicMessages[f.Code]
}

// body is the public JSON of f (TransferFailure.to_public_dict).
func (f Failure) body() map[string]any {
	out := map[string]any{"error_code": string(f.Code), "error": f.text(), "retryable": f.Retryable()}
	if f.LimitKind != "" {
		out["limit_kind"] = string(f.LimitKind)
		out["limit_bytes"] = f.LimitBytes
		if f.ActualBytes >= 0 {
			out["actual_bytes"] = f.ActualBytes
		}
	}
	return out
}

// asFault is f as the error of a realtime request: the code, the text and
// the remaining members in the details.
func (f Failure) asFault() *fault.Error {
	e := fault.New(f.Code, f.text())
	e.Details = map[string]any{"retryable": f.Retryable()}
	if f.LimitKind != "" {
		e.Details["limit_kind"] = string(f.LimitKind)
		e.Details["limit_bytes"] = f.LimitBytes
		if f.ActualBytes >= 0 {
			e.Details["actual_bytes"] = f.ActualBytes
		}
	}
	return e
}

// Causes of a cancellation, so the failure tells why the transfer ended.
var (
	errCancelled = fault.New(fault.FileCancelled, "")
	errRevoked   = fault.New(fault.SourceUnavailable, "")
)

// endedBy returns the failure of a transfer whose context ended: the cause
// it was cancelled with, else the classification of err.
func endedBy(ctx context.Context, err error, op operation) Failure {
	if cause := context.Cause(ctx); cause != nil && ctx.Err() != nil {
		if fe, ok := fault.From(cause); ok {
			return newFailure(fe.Code, op)
		}
	}
	return failureOf(err, op)
}
