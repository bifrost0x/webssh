package operations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// The instance view of the administration (C-AOPS-05 to -09): what runs,
// and the narrowly scoped actions on it. Each source is a consumer
// interface; the composition root passes the realtime server, the
// terminal manager, the transfer manager and the job registry. A nil
// source is not built yet; its part of the view is empty.

// ConnectionRef is the opaque reference of a realtime connection in the
// view and in the routes, sha256("admin-connection:"+id) in hex as in the
// Python release (app/operations.py). Raw ids never leave the server.
func ConnectionRef(connectionID string) string {
	return ref("admin-connection:" + connectionID)
}

// SessionRef is the opaque reference of an SSH session,
// sha256("admin-ssh:"+id) in hex.
func SessionRef(sessionID string) string {
	return ref("admin-ssh:" + sessionID)
}

func ref(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// LiveConnection is one realtime connection.
type LiveConnection struct {
	ID        string // the connection id; the view shows ConnectionRef(ID)
	UserID    int64
	CreatedAt time.Time
}

// Connections lists and ends realtime connections (internal/realtime).
// Disconnect reports false when the connection was already gone; an error
// means the effect is not confirmed (fault.ActionUnconfirmed).
type Connections interface {
	Live() []LiveConnection
	Disconnect(ctx context.Context, id string) (bool, error)
}

// LiveSession is one SSH session.
type LiveSession struct {
	ID        string
	UserID    int64 // 0 for a session without an owner
	Target    string
	Tmux      bool
	CreatedAt time.Time
}

// Sessions lists and closes SSH sessions (internal/terminal). Disconnect
// keeps the tmux session on the host (kill_tmux=False) and tells the owner
// with the event the Python release sent.
type Sessions interface {
	Live() (active int, items []LiveSession)
	Disconnect(ctx context.Context, id string) error
}

// LiveTransfer is one HTTP or host-to-host transfer.
type LiveTransfer struct {
	ID        string
	UserID    int64
	Kind      string
	State     string
	Bytes     int64
	Total     int64
	CreatedAt time.Time
}

// Transfers lists and cancels transfers (internal/transfer). Cancel
// returns whether the cancel was accepted and the resulting state;
// "unavailable" means the transfer no longer exists.
type Transfers interface {
	Live() []LiveTransfer
	Cancel(ctx context.Context, id string) (accepted bool, state string, err error)
}

// LiveJob is one registered background job.
type LiveJob struct {
	Name    string
	Running bool
	LastRun time.Time
	NextRun time.Time
	LastErr string // a fault code, never error text
}

// Jobs lists the background jobs (internal/jobs).
type Jobs interface {
	Live() []LiveJob
}

// QuotaUse is the use of one quota kind.
type QuotaUse struct {
	Kind  string
	Used  int64
	Limit int64
}

// Quotas reports the instance-wide use of the quotas (internal/quota).
type Quotas interface {
	Use(ctx context.Context) ([]QuotaUse, error)
}
