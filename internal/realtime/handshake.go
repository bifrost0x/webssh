package realtime

import (
	"bufio"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// closeGrace bounds the close handshake. The library allows 5 s to write
// the close frame and 5 s more for the answer, and CloseNow does nothing
// once Close has begun. A client that stopped reading would hold its
// connection slot and goroutines that long; after closeGrace the raw
// connection is closed instead.
const closeGrace = 2 * time.Second

// hijackRecorder keeps the raw connection the WebSocket library takes
// over, so that a close can be bounded.
type hijackRecorder struct {
	http.ResponseWriter
	raw net.Conn
}

// Hijack implements http.Hijacker.
func (h *hijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	c, brw, err := http.NewResponseController(h.ResponseWriter).Hijack()
	h.raw = c
	return c, brw, err
}

// upgrade accepts the WebSocket with acceptOptions and returns the raw
// connection beside it.
func upgrade(w http.ResponseWriter, r *http.Request, subprotocols []string) (*websocket.Conn, net.Conn, error) {
	rec := &hijackRecorder{ResponseWriter: w}
	ws, err := websocket.Accept(rec, r, acceptOptions(subprotocols))
	if err != nil {
		return nil, nil, err
	}
	return ws, rec.raw, nil
}

// closeBounded performs the close handshake for at most closeGrace and
// then drops the connection.
func closeBounded(ws *websocket.Conn, raw net.Conn, code websocket.StatusCode, reason string) {
	force := time.AfterFunc(closeGrace, func() { _ = raw.Close() })
	defer force.Stop()
	_ = ws.Close(code, reason)
}

// pickVersion returns the highest offered schema version this build
// speaks, or 0.
func pickVersion(r *http.Request) int {
	best := 0
	for _, v := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, tok := range splitTokens(v) {
			if n, ok := protocol.ParseSubprotocol(tok); ok && n == protocol.Version && n > best {
				best = n
			}
		}
	}
	return best
}

// splitTokens splits a comma-separated header value and trims spaces and
// tabs (RFC 9110, section 5.6.1).
func splitTokens(v string) []string {
	var out []string
	for tok := range strings.SplitSeq(v, ",") {
		if tok = strings.Trim(tok, " \t"); tok != "" {
			out = append(out, tok)
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
