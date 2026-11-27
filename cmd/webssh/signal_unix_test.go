package main

import (
	"syscall"
	"testing"
	"time"
)

// TestShutdownSignals sends real signals to the test process; the handlers
// installed by withShutdownSignals keep it alive.
func TestShutdownSignals(t *testing.T) {
	ctx, force, stop := withShutdownSignals(t.Context())
	defer stop()
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("first SIGTERM did not end the context")
	}
	select {
	case <-force:
		t.Fatal("one signal forced the shutdown")
	case <-time.After(50 * time.Millisecond):
	}
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case <-force:
	case <-time.After(5 * time.Second):
		t.Fatal("second signal did not force the shutdown")
	}
	// Further signals are absorbed while the handlers are installed.
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
}

func TestShutdownSignalsStopWithoutSignal(t *testing.T) {
	ctx, _, stop := withShutdownSignals(t.Context())
	stop()
	if ctx.Err() == nil {
		t.Error("context still open after stop")
	}
}
