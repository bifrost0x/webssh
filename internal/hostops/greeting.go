package hostops

import (
	"context"
	"time"
)

// readGreeting reads what the server sends on its own, without sending
// anything, until enough says the data is complete, limit bytes arrived,
// the server closed or timeout passed, and closes conn.
func readGreeting(ctx context.Context, conn Conn, limit int, timeout time.Duration, enough func([]byte) bool) []byte {
	defer conn.Close()
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetReadDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Unix(1, 0)) })
	defer stop()
	buf := make([]byte, 0, limit)
	for len(buf) < limit && !enough(buf) {
		n, err := conn.Read(buf[len(buf):limit])
		buf = buf[:len(buf)+n]
		if err != nil {
			break
		}
	}
	return buf
}
