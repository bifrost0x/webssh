package realtime

import (
	"context"
	"encoding/binary"
	"os"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// fakeTerminal is the backend of the load test: terminal.open starts an
// output stream on the channel until the connection ends, and input
// frames are echoed as output, like a shell with echo on.
func fakeTerminal(s *Server) {
	s.Mount(protocol.Handle("fake.open", protocol.Spec{Async: true, Timeout: time.Hour},
		func(ctx context.Context, peer protocol.Peer, _ protocol.Empty) (*protocol.Empty, error) {
			data := make([]byte, 4<<10)
			tick := time.NewTicker(20 * time.Millisecond)
			defer tick.Stop()
			for seq := uint64(1); ; seq++ {
				select {
				case <-ctx.Done():
					return nil, nil
				case <-tick.C:
					f := protocol.AppendFrame(nil, protocol.Frame{Kind: protocol.KindOutput, Channel: 1, Seq: seq, Data: data})
					if peer.SendBinary(f) != nil {
						return nil, nil
					}
				}
			}
		}))
	s.HandleBinary(func(peer protocol.Peer, b []byte) error {
		f, err := protocol.DecodeFrame(b, 1024)
		if err != nil {
			return err
		}
		if f.Kind == protocol.KindInput {
			out := protocol.AppendFrame(nil, protocol.Frame{Kind: protocol.KindOutput, Channel: 2, Seq: f.Seq, Data: f.Data})
			return peer.SendBinary(out)
		}
		return nil
	})
}

// TestLoad opens many sessions against the fake backend at once, keeps
// them streaming, measures echo round trips and memory, and checks that
// everything is released afterwards. WEBSSH_REALTIME_LOAD sets the number
// of sessions (default 500).
func TestLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("load test")
	}
	n := 500
	if v := os.Getenv("WEBSSH_REALTIME_LOAD"); v != "" {
		var err error
		if n, err = strconv.Atoi(v); err != nil || n <= 0 {
			t.Fatalf("WEBSSH_REALTIME_LOAD=%q", v)
		}
	}
	base := settledGoroutines(t, 0)
	// The keepalive has its own tests. Here it would only add a deadline
	// that a starved machine misses once the echo grace below runs past
	// the ping interval: the pong waits behind the output stream.
	e := newEnv(t, Config{MaxConns: n + 10, MaxConnsPerUser: 10, PingInterval: time.Hour}, fakeTerminal)

	start := time.Now()
	clients := make([]*client, n)
	var wg sync.WaitGroup
	sem := make(chan struct{}, 32) // parallel handshakes
	for i := range n {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			c, err := e.tryOpen(int64(i/10+1), "load-"+strconv.Itoa(i))
			if err != nil {
				t.Error(err)
				return
			}
			clients[i] = c
		})
	}
	wg.Wait()
	setup := time.Since(start)
	if t.Failed() {
		t.FailNow()
	}

	var received atomic.Int64
	rtts := make([][]time.Duration, n)
	sessions := make([]*loadSession, n)
	stop := make(chan struct{})
	var readers sync.WaitGroup
	for i, c := range clients {
		c.write(`{"v":1,"t":"fake.open","id":"o"}`)
		sess := &loadSession{c: c}
		sessions[i] = sess
		readers.Go(func() { rtts[i] = sess.read(&received) })
		wg.Go(func() { sess.type_(stop) })
	}
	time.Sleep(3 * time.Second)
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	peakG := runtime.NumGoroutine()
	open := e.srv.Stats().Conns
	// Every session must see an echo while the streams run. On a loaded
	// machine (the race detector, many packages at once) a session's
	// typing goroutine can be starved for the whole window, or its last
	// keystrokes are still in flight when the window ends; that is the
	// scheduler, not the server. So typing and streaming go on until each
	// session has an echo, bounded by echoGrace; a session that never gets
	// one still fails the test.
	echoed := func() int {
		k := 0
		for _, sess := range sessions {
			if sess.echoes.Load() > 0 {
				k++
			}
		}
		return k
	}
	late, graceStart := n-echoed(), time.Now()
	for deadline := graceStart.Add(echoGrace); echoed() < n && time.Now().Before(deadline); {
		time.Sleep(50 * time.Millisecond)
	}
	if late > 0 {
		t.Logf("%d sessions had no echo after the window; the last one after %v more", late, time.Since(graceStart).Round(time.Millisecond))
	}
	close(stop)
	wg.Wait()
	for _, c := range clients {
		_ = c.ws.Close(websocket.StatusNormalClosure, "")
	}
	readers.Wait()

	var all []time.Duration
	failed := 0
	for _, r := range rtts {
		if len(r) == 0 {
			failed++
		}
		all = append(all, r...)
	}
	slices.Sort(all)
	if failed > 0 || len(all) == 0 || open != n {
		for i, sess := range sessions {
			if len(rtts[i]) == 0 {
				t.Errorf("session %d: %d keystrokes sent, no echo, read ended with %v", i, sess.sent.Load(), sess.readErr)
			}
		}
		t.Fatalf("%d sessions without echo, %d samples, %d open", failed, len(all), open)
	}
	t.Logf("sessions %d, setup %v, open %d, output %.1f MiB in 3 s, echo p50 %v p95 %v p99 %v (n=%d), heap in use %.1f MiB, sys %.1f MiB, goroutines %d (%.1f per session)",
		n, setup.Round(time.Millisecond), open, float64(received.Load())/(1<<20),
		all[len(all)/2], all[len(all)*95/100], all[len(all)*99/100], len(all),
		float64(ms.HeapInuse)/(1<<20), float64(ms.Sys)/(1<<20), peakG, float64(peakG-base)/float64(n))

	waitFor(t, func() bool { return e.srv.Stats().Conns == 0 })
	sctx, scancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer scancel()
	if err := e.srv.Shutdown(sctx); err != nil {
		t.Fatal(err)
	}
	e.ts.Close()
	if after := settledGoroutines(t, base); after > base {
		t.Fatalf("goroutines %d after the load, %d before", after, base)
	}
}

// echoGrace bounds how long the load test waits after its measuring
// window for sessions that have not seen an echo yet.
const echoGrace = 30 * time.Second

// loadSession types one keystroke every 100 ms and measures its echo.
type loadSession struct {
	c      *client
	mu     sync.Mutex
	pend   map[uint64]time.Time
	sent   atomic.Int64
	echoes atomic.Int64
	// readErr is why the read loop ended; read by the test after
	// readers.Wait.
	readErr error
}

func (l *loadSession) type_(stop <-chan struct{}) {
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for iseq := uint64(1); ; iseq++ {
		select {
		case <-stop:
			return
		case <-tick.C:
		}
		in := protocol.AppendFrame(nil, protocol.Frame{Kind: protocol.KindInput, Channel: 2, Seq: iseq, Data: []byte("x")})
		l.mu.Lock()
		if l.pend == nil {
			l.pend = map[uint64]time.Time{}
		}
		l.pend[iseq] = time.Now()
		l.mu.Unlock()
		if l.c.ws.Write(context.Background(), websocket.MessageBinary, in) != nil {
			return
		}
		l.sent.Add(1)
	}
}

// read consumes the stream until the connection closes. Reads have no
// deadline: the library drops a connection whose read context ends.
func (l *loadSession) read(received *atomic.Int64) []time.Duration {
	var rtts []time.Duration
	for {
		typ, b, err := l.c.ws.Read(context.Background())
		if err != nil {
			l.readErr = err
			return rtts
		}
		received.Add(int64(len(b)))
		if typ != websocket.MessageBinary || len(b) < protocol.HeaderLen || binary.BigEndian.Uint32(b[2:6]) != 2 {
			continue
		}
		seq := binary.BigEndian.Uint64(b[6:14])
		l.mu.Lock()
		if at, ok := l.pend[seq]; ok {
			rtts = append(rtts, time.Since(at))
			delete(l.pend, seq)
			l.echoes.Add(1)
		}
		l.mu.Unlock()
	}
}
