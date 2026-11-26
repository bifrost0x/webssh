package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// shutdownSignals are the signals that stop the server: SIGTERM from
// docker stop and service managers, SIGINT from a terminal.
var shutdownSignals = []os.Signal{syscall.SIGTERM, os.Interrupt}

// withShutdownSignals returns a context that ends with the first shutdown
// signal and a channel that closes with the second, which cuts the graceful
// shutdown short. The handlers stay installed until stop is called: as PID 1
// in a container the kernel ignores signals without a handler, so restoring
// the default after the first signal would make a second one do nothing.
func withShutdownSignals(parent context.Context) (ctx context.Context, force <-chan struct{}, stop func()) {
	ctx, cancel := context.WithCancel(parent)
	forced := make(chan struct{})
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, shutdownSignals...)
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		received := 0
		for {
			select {
			case <-ch:
				received++
				switch received {
				case 1:
					cancel()
				case 2:
					close(forced)
				}
			case <-done:
				return
			}
		}
	}()
	return ctx, forced, func() {
		signal.Stop(ch)
		close(done)
		<-finished
		cancel()
	}
}
