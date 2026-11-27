package main

import (
	"io"
	"io/fs"
	"runtime/debug"

	"github.com/bifrost0x/webssh/internal/platform"
)

// applyMemoryLimit gives the runtime a soft memory limit below the memory
// limit of the container (mem_limit), so that the garbage collector works
// harder before the kernel kills the process, for example during the
// one-time migration of large legacy stores. GOMEMLIMIT, when set, is the
// operator's choice and the runtime has applied it already. It returns
// the limit set, 0 for none.
func applyMemoryLimit(lookup func(string) (string, bool), sys fs.FS, stderr io.Writer) int64 {
	if _, set := lookup("GOMEMLIMIT"); set {
		return 0
	}
	limit, ok, err := platform.MemoryLimit(sys)
	if err != nil {
		write(stderr, "webssh: memory limit: "+err.Error()+"\n")
		return 0
	}
	if !ok {
		return 0
	}
	debug.SetMemoryLimit(limit)
	return limit
}
