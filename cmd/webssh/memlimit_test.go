package main

import (
	"io"
	"math"
	"runtime/debug"
	"testing"
	"testing/fstest"
)

// Not parallel: the memory limit belongs to the whole test process.
func TestApplyMemoryLimit(t *testing.T) {
	previous := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(previous) })
	sys := fstest.MapFS{
		"proc/self/cgroup":         {Data: []byte("0::/\n")},
		"sys/fs/cgroup/memory.max": {Data: []byte("2147483648\n")},
	}
	unset := func(string) (string, bool) { return "", false }
	if got := applyMemoryLimit(unset, sys, io.Discard); got != 1536<<20 || debug.SetMemoryLimit(-1) != 1536<<20 {
		t.Fatalf("limit %d", got)
	}
	debug.SetMemoryLimit(math.MaxInt64)
	set := func(name string) (string, bool) { return "1GiB", name == "GOMEMLIMIT" }
	if got := applyMemoryLimit(set, sys, io.Discard); got != 0 || debug.SetMemoryLimit(-1) != math.MaxInt64 {
		t.Fatalf("GOMEMLIMIT overridden: %d", got)
	}
	if got := applyMemoryLimit(unset, fstest.MapFS{}, io.Discard); got != 0 || debug.SetMemoryLimit(-1) != math.MaxInt64 {
		t.Fatalf("limit without cgroup: %d", got)
	}
}
