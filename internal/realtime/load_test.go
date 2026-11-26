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
	e := newEnv(t, Config{MaxConns: n + 10, MaxConnsPerUser: 10}, fakeTerminal)

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
	stop := make(chan struct{})
	var readers sync.WaitGroup
	for i, c := range clients {
		c.write(`{"v":1,"t":"fake.open","id":"o"}`)
		sess := &loadSession{c: c}
		readers.Go(func() { rtts[i] = sess.read(&received) })
		wg.Go(func() { sess.type_(stop) })
	}
	time.Sleep(3 * time.Second)
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	peakG := runtime.NumGoroutine()
	open := e.srv.Stats().Conns
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

// loadSession types one keystroke every 100 ms and measures its echo.
type loadSession struct {
	c    *client
	mu   sync.Mutex
	sent map[uint64]time.Time
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
		if l.sent == nil {
			l.sent = map[uint64]time.Time{}
		}
		l.sent[iseq] = time.Now()
		l.mu.Unlock()
		if l.c.ws.Write(context.Background(), websocket.MessageBinary, in) != nil {
			return
		}
	}
}

// read consumes the stream until the connection closes. Reads have no
// deadline: the library drops a connection whose read context ends.
func (l *loadSession) read(received *atomic.Int64) []time.Duration {
	var rtts []time.Duration
	for {
		typ, b, err := l.c.ws.Read(context.Background())
		if err != nil {
			return rtts
		}
		received.Add(int64(len(b)))
		if typ != websocket.MessageBinary || len(b) < protocol.HeaderLen || binary.BigEndian.Uint32(b[2:6]) != 2 {
			continue
		}
		seq := binary.BigEndian.Uint64(b[6:14])
		l.mu.Lock()
		if at, ok := l.sent[seq]; ok {
			rtts = append(rtts, time.Since(at))
			delete(l.sent, seq)
		}
		l.mu.Unlock()
	}
}
