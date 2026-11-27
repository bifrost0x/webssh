package platform

import (
	"testing"
	"testing/fstest"
)

func TestMemoryLimit(t *testing.T) {
	t.Parallel()
	file := func(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s)} }
	tests := []struct {
		name  string
		files fstest.MapFS
		want  int64
		ok    bool
		fails bool
	}{
		{name: "no proc", files: fstest.MapFS{}},
		{name: "v2 container root", files: fstest.MapFS{
			"proc/self/cgroup":         file("0::/\n"),
			"sys/fs/cgroup/memory.max": file("2147483648\n"),
		}, want: 1610612736, ok: true},
		{name: "v2 unlimited", files: fstest.MapFS{
			"proc/self/cgroup":         file("0::/\n"),
			"sys/fs/cgroup/memory.max": file("max\n"),
		}},
		{name: "v2 limit on a parent", files: fstest.MapFS{
			"proc/self/cgroup": file("0::/system.slice/docker-1.scope\n"),
			"sys/fs/cgroup/system.slice/docker-1.scope/memory.max": file("max\n"),
			"sys/fs/cgroup/system.slice/memory.max":                file("1073741824\n"),
		}, want: 805306368, ok: true},
		{name: "v2 smallest wins", files: fstest.MapFS{
			"proc/self/cgroup":             file("0::/a/b\n"),
			"sys/fs/cgroup/a/b/memory.max": file("268435456\n"),
			"sys/fs/cgroup/a/memory.max":   file("1073741824\n"),
		}, want: 201326592, ok: true},
		{name: "v1", files: fstest.MapFS{
			"proc/self/cgroup": file("12:memory:/docker/abc\n11:cpu,cpuacct:/docker/abc\n"),
			"sys/fs/cgroup/memory/docker/abc/memory.limit_in_bytes": file("536870912\n"),
		}, want: 402653184, ok: true},
		{name: "v1 unlimited", files: fstest.MapFS{
			"proc/self/cgroup":                           file("12:memory:/\n"),
			"sys/fs/cgroup/memory/memory.limit_in_bytes": file("9223372036854771712\n"),
		}},
		{name: "garbage", files: fstest.MapFS{
			"proc/self/cgroup":         file("0::/\n"),
			"sys/fs/cgroup/memory.max": file("lots\n"),
		}, fails: true},
		{name: "negative", files: fstest.MapFS{
			"proc/self/cgroup":         file("0::/\n"),
			"sys/fs/cgroup/memory.max": file("-1\n"),
		}, fails: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok, err := MemoryLimit(tc.files)
			if (err != nil) != tc.fails || ok != tc.ok || got != tc.want {
				t.Fatalf("MemoryLimit = %d, %v, %v; want %d, %v, fails %v", got, ok, err, tc.want, tc.ok, tc.fails)
			}
		})
	}
}
