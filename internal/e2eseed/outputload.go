package e2eseed

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// Realtime message types of the test hooks. They exist only in the e2e
// build; the compatibility shim maps the Socket.IO events of the specs
// (e2e_output_load, e2e_output_load_done, e2e_workspace_restore) to them.
const (
	TypeOutputLoad       = "e2e.output_load"
	TypeOutputLoadDone   = "e2e.output_load_done"
	TypeWorkspaceRestore = "e2e.workspace_restore"
)

// Parameters of the output load, as in tests/e2e/output_load.py.
const (
	loadStreams  = 20
	loadFrames   = 240
	loadInterval = 50 * time.Millisecond // 20 Hz
	loadBudget   = 35 * time.Second
	loadSample   = 10 * time.Millisecond
)

// OutputFlow is the terminal output path the load runs through, provided
// by internal/terminal: the same flow control and acknowledgement budget
// as real sessions.
type OutputFlow interface {
	// Emit sends one output frame of a synthetic stream to the peer. It
	// blocks while flow control holds the stream back and returns an error
	// when ctx ends or the frame cannot be delivered.
	Emit(ctx context.Context, peer protocol.Peer, stream string, seq uint64, data []byte) error
	// InFlight is the number of output messages sent to the peer and not
	// yet acknowledged.
	InFlight(peer protocol.Peer) int
}

// OutputLoadDone is the payload of TypeOutputLoadDone.
type OutputLoadDone struct {
	Counts    []int `json:"counts"`
	Peak      int   `json:"peak"`
	ElapsedMS int64 `json:"elapsed_ms"`
	Aborted   bool  `json:"aborted"`
}

// OK is the result of the hook requests.
type OK struct {
	OK bool `json:"ok"`
}

// outputLoad runs at most one load per connection, so a client cannot
// start unbounded producers.
type outputLoad struct {
	flow    OutputFlow
	mu      sync.Mutex
	running map[uint64]bool
}

// OutputLoadRoute is the counterpart of the socket_output_load hook: the
// request starts 20 synthetic terminal streams of 240 frames at 20 Hz on
// the caller's connection and answers at once; TypeOutputLoadDone reports
// the frames delivered per stream, the peak of unacknowledged messages,
// the duration and whether the 35 s budget stopped the load.
func OutputLoadRoute(flow OutputFlow) protocol.Route {
	l := &outputLoad{flow: flow, running: map[uint64]bool{}}
	return protocol.Handle(TypeOutputLoad, protocol.Spec{}, l.start)
}

func (l *outputLoad) start(ctx context.Context, peer protocol.Peer, _ protocol.Empty) (OK, error) {
	if _, err := principal.Require(ctx); err != nil {
		return OK{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.running[peer.ID()] {
		return OK{}, fault.New(fault.Busy, "")
	}
	l.running[peer.ID()] = true
	go func() {
		done := runOutputLoad(peer.Context(), l.flow, peer)
		l.mu.Lock()
		delete(l.running, peer.ID())
		l.mu.Unlock()
		// The connection may be gone; there is nobody left to tell.
		_ = peer.SendEvent(TypeOutputLoadDone, done)
	}()
	return OK{OK: true}, nil
}

// runOutputLoad produces the streams and returns when all of them ended.
// It stops early when ctx ends or the budget is exceeded.
func runOutputLoad(ctx context.Context, flow OutputFlow, peer protocol.Peer) OutputLoadDone {
	ctx, stop := context.WithCancel(ctx)
	defer stop()
	started := time.Now()
	counts := make([]int, loadStreams)
	var wg sync.WaitGroup
	for i := range loadStreams {
		wg.Go(func() { counts[i] = produceStream(ctx, flow, peer, i, started) })
	}
	finished := make(chan struct{})
	go func() { wg.Wait(); close(finished) }()

	peak, aborted := 0, false
	tick := time.NewTicker(loadSample)
	defer tick.Stop()
	for {
		peak = max(peak, flow.InFlight(peer))
		select {
		case <-finished:
			return OutputLoadDone{Counts: counts, Peak: peak, ElapsedMS: time.Since(started).Milliseconds(), Aborted: aborted}
		case <-tick.C:
			if !aborted && time.Since(started) > loadBudget {
				aborted = true
				stop()
			}
		}
	}
}

// produceStream sends the frames of one stream on absolute 20 Hz slots,
// also after backpressure, and returns how many were delivered.
func produceStream(ctx context.Context, flow OutputFlow, peer protocol.Peer, index int, started time.Time) int {
	stream := fmt.Sprintf("load-%d", index)
	completed := 0
	for seq := 1; seq <= loadFrames; seq++ {
		wait := time.Until(started.Add(time.Duration(seq-1) * loadInterval))
		if wait > 0 {
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return completed
			case <-t.C:
			}
		}
		if ctx.Err() != nil || flow.Emit(ctx, peer, stream, uint64(seq), loadFrame(index, seq)) != nil {
			return completed
		}
		completed = seq
	}
	return completed
}

// loadFrame is a full-screen redraw of 24 coloured lines, the first one
// switching to the alternate screen, as in output_load.py.
func loadFrame(index, seq int) []byte {
	var b strings.Builder
	if seq == 1 {
		b.WriteString("\x1b[?1049h\x1b[?2004h\x1b[?1h")
	}
	b.WriteString("\x1b[H")
	line := "\x1b[32m" + strings.Repeat("x", 100) + "\x1b[0m\r\n"
	for range 24 {
		b.WriteString(line)
	}
	fmt.Fprintf(&b, "\x1b[Hstream-%d frame-%d END", index, seq)
	return []byte(b.String())
}
