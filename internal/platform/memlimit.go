package platform

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"path"
	"strconv"
	"strings"
)

// memoryLimitShare is the part of the cgroup memory limit the Go runtime
// may use as its soft limit. The rest is left to memory the runtime does
// not account for: the binary, the SQLite engine and the page cache of
// the kernel charged to the container.
const (
	memoryLimitNum = 3
	memoryLimitDen = 4
)

// MemoryLimit returns the soft memory limit for the Go runtime derived from
// the memory limit of the cgroup the process runs in (for example
// mem_limit of a Compose file): three quarters of the smallest limit on
// the way from the process's cgroup to the root. ok is false when no
// limit is set.
//
// sys is the root of the file system (os.DirFS("/") in production); both
// cgroup v2 (memory.max) and cgroup v1 (memory.limit_in_bytes) are read.
// Without the files, for example outside a container, there is no limit.
func MemoryLimit(sys fs.FS) (limit int64, ok bool, err error) {
	data, err := fs.ReadFile(sys, "proc/self/cgroup")
	if errors.Is(err, fs.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("platform: read the cgroup of the process: %w", err)
	}
	unified, v1, err := cgroupPaths(data)
	if err != nil {
		return 0, false, err
	}
	var lowest int64 = math.MaxInt64
	found := false
	visit := func(root, dir, file string) error {
		for p := path.Join(root, dir); ; p = path.Dir(p) {
			n, set, err := limitFile(sys, path.Join(p, file))
			if err != nil {
				return err
			}
			if set && n < lowest {
				lowest, found = n, true
			}
			if p == root {
				return nil
			}
		}
	}
	if unified != "" {
		if err := visit("sys/fs/cgroup", unified, "memory.max"); err != nil {
			return 0, false, err
		}
	}
	if v1 != "" {
		if err := visit("sys/fs/cgroup/memory", v1, "memory.limit_in_bytes"); err != nil {
			return 0, false, err
		}
	}
	if !found {
		return 0, false, nil
	}
	return lowest / memoryLimitDen * memoryLimitNum, true, nil
}

// cgroupPaths returns the cgroup v2 path ("0::/path") and the path of the
// v1 memory controller from /proc/self/cgroup.
func cgroupPaths(data []byte) (unified, memory string, err error) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), ":", 3)
		if len(parts) != 3 {
			continue
		}
		p := strings.TrimPrefix(path.Clean("/"+parts[2]), "/")
		switch {
		case parts[0] == "0" && parts[1] == "":
			unified = cgroupDir(p)
		case strings.Contains(","+parts[1]+",", ",memory,"):
			memory = cgroupDir(p)
		}
	}
	if err := sc.Err(); err != nil {
		return "", "", fmt.Errorf("platform: read the cgroup of the process: %w", err)
	}
	return unified, memory, nil
}

// cgroupDir maps the root cgroup ("") to ".", which path.Join drops.
func cgroupDir(p string) string {
	if p == "" {
		return "."
	}
	return p
}

// limitFile reads one limit file; "max", a missing file and values that
// mean "no limit" in cgroup v1 (close to the largest int64) are no limit.
func limitFile(sys fs.FS, name string) (int64, bool, error) {
	data, err := fs.ReadFile(sys, name)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("platform: read %s: %w", name, err)
	}
	text := strings.TrimSpace(string(data))
	if text == "max" || text == "" {
		return 0, false, nil
	}
	n, err := strconv.ParseInt(text, 10, 64)
	if err != nil || n <= 0 {
		return 0, false, fmt.Errorf("platform: %s holds %q, not a memory limit", name, text)
	}
	if n >= math.MaxInt64/2 {
		return 0, false, nil
	}
	return n, true, nil
}
