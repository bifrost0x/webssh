package smb

import (
	"context"
	"errors"

	"github.com/bifrost0x/webssh/internal/fault"
)

// step marks the point of a mutation after which its outcome depends on
// the server: once the mutating request has been handed to the transport
// a lost reply leaves it unknown.
type step struct{ sent bool }

// send marks the mutating request as handed to the transport.
func (s *step) send() { s.sent = true }

// mutate runs one mutation under the mutation deadline (10 seconds, as in
// the Python release). Before the mutating request was sent, the
// deadline is TIMEOUT and nothing changed. After it, a missing answer
// (deadline, cancellation, broken transport) is OUTCOME_UNKNOWN and the
// session is tainted: the server may still carry the request out, and a
// handle it created may be open, so no further request runs on the
// session (Python shut the socket down). A status the server sent is a
// definite answer and passes unchanged.
func (b *Backend) mutate(ctx context.Context, fn func(ctx context.Context, s *step) error) error {
	if err := b.alive(); err != nil {
		return err
	}
	mctx, cancel := context.WithTimeout(ctx, b.mutation)
	defer cancel()
	var s step
	err := fn(mctx, &s)
	if err == nil {
		return nil
	}
	if s.sent && unanswered(err) {
		b.taint()
		return fail(fault.OutcomeUnknown, PhaseFileOperation, "OutcomeUnknown", err)
	}
	return err
}

// causeNotApplied marks a lost reply whose request was found not carried
// out: the answer is then known.
const causeNotApplied = "NotApplied"

// unanswered reports whether err means that no answer of the server
// arrived, as opposed to a status the server sent.
func unanswered(err error) bool {
	if d, ok := errors.AsType[*diagnostic](err); ok && (d.status != 0 || d.cause == causeNotApplied) {
		return false
	}
	switch fault.CodeOf(err) {
	case fault.FileTimeout, fault.FileCancelled, fault.SourceUnavailable, fault.SMBConnectCancelled:
		return true
	case fault.OperationFailed:
		d, ok := errors.AsType[*diagnostic](err)
		return ok && (d.cause == "ProtocolError" || d.cause == "ConnectionError")
	}
	return false
}

// reconcile settles a rename whose reply was lost through the handle it
// ran on: where reports whether the object is now at the destination
// (applied) and whether that could be read at all (known). It returns nil
// when the rename is found carried out, TIMEOUT when it is found not
// carried out, and OUTCOME_UNKNOWN otherwise. Unless the rename is found
// carried out, the session is tainted: a request without an answer may
// still be pending on it, as the deadline of the Python release assumed.
// A status the server sent passes unchanged.
func (b *Backend) reconcile(err error, where func() (applied, known bool)) error {
	if !unanswered(err) {
		return err
	}
	applied, known := where()
	if known && applied {
		return nil
	}
	b.taint()
	if known {
		return fail(fault.FileTimeout, PhaseFileOperation, causeNotApplied, err)
	}
	return fail(fault.OutcomeUnknown, PhaseFileOperation, "OutcomeUnknown", err)
}
