//go:build lab

package sftp_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"testing"

	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/files/sftp"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// The throughput benchmarks move 200 MiB, as the Python baseline did
// (download 4.9 MiB/s: sequential 64 KiB reads without prefetch):
//
//	go test -tags lab -run '^$' -bench Lab -benchtime 3x ./internal/files/sftp
//
// Prefetch 1 is the sequential pattern of the Python release.
const benchSize = 200 << 20

var benchVariants = []sftp.Options{
	{ChunkBytes: 64 << 10, Prefetch: 1},
	{ChunkBytes: 32 << 10, Prefetch: 64},
	{ChunkBytes: 64 << 10, Prefetch: 16},
	{ChunkBytes: 64 << 10, Prefetch: 32},
	{ChunkBytes: 64 << 10, Prefetch: 64},
	{ChunkBytes: 255 << 10, Prefetch: 16},
}

func benchTargets(b *testing.B, r *rig) map[string]client.Target {
	inner := lab(b).Services["ssh-inner"]
	bastion := lab(b).Services["ssh-bastion"]
	return map[string]client.Target{
		"modern": r.modern(b),
		"jump": {
			Jumps: []client.Hop{{Host: bastion.Host, Port: bastion.Port, User: "pwuser", Auth: client.Auth{Password: r.pw}}},
			Hop:   client.Hop{Host: inner.InternalHost, Port: inner.InternalPort, User: "pwuser", Auth: client.Auth{Password: r.pw}},
		},
	}
}

func BenchmarkLabTransfer(b *testing.B) {
	data := make([]byte, benchSize)
	_, _ = rand.Read(data)
	for _, name := range []string{"modern", "jump"} {
		for _, o := range benchVariants {
			label := fmt.Sprintf("%s/chunk=%dK/prefetch=%d", name, o.ChunkBytes>>10, o.Prefetch)
			r := newRig(b, o)
			be := r.open(b, benchTargets(b, r)[name])
			dir := workdir(b, be)
			p := dir + "/bench"
			b.Run("upload/"+label, func(b *testing.B) {
				b.SetBytes(benchSize)
				for b.Loop() {
					if _, err := be.Write(context.Background(), p, bytes.NewReader(data), files.WriteOptions{Size: benchSize}); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("download/"+label, func(b *testing.B) {
				b.SetBytes(benchSize)
				for b.Loop() {
					rd, err := be.Open(context.Background(), p, files.Range{Length: -1})
					if err != nil {
						b.Fatal(err)
					}
					n, err := io.Copy(io.Discard, rd)
					_ = rd.Close()
					if err != nil || n != benchSize {
						b.Fatalf("%d %v", n, err)
					}
				}
			})
		}
	}
}
